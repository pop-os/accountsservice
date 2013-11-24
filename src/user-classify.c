/*
 * Copyright (C) 2009-2010 Red Hat, Inc.
 * Copyright (C) 2013 Canonical Limited
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the licence, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 *
 * Authors: Ryan Lortie <desrt@desrt.ca>
 *          Matthias Clasen <mclasen@redhat.com>
 */

#include "config.h"

#include "user-classify.h"

#include <string.h>

#ifdef ENABLE_USER_HEURISTICS
static const char *default_excludes[] = {
        "bin",
        "root",
        "daemon",
        "adm",
        "lp",
        "sync",
        "shutdown",
        "halt",
        "mail",
        "news",
        "uucp",
        "operator",
        "nobody",
        "nobody4",
        "noaccess",
        "postgres",
        "pvm",
        "rpm",
        "nfsnobody",
        "pcap",
        "mysql",
        "ftp",
        "games",
        "man",
        "at",
        "gdm",
        "gnome-initial-setup"
};

#define PATH_NOLOGIN "/sbin/nologin"
#define PATH_FALSE "/bin/false"

static gboolean
user_classify_is_excluded_by_heuristics (const gchar *username,
                                         const gchar *shell,
                                         const gchar *password_hash)
{
        static GHashTable *exclusions;
        gboolean ret = FALSE;

        if (exclusions == NULL) {
                guint i;

                exclusions = g_hash_table_new (g_str_hash, g_str_equal);

                for (i = 0; i < G_N_ELEMENTS (default_excludes); i++) {
                        g_hash_table_add (exclusions, (gpointer) default_excludes[i]);
                }
        }

        if (g_hash_table_contains (exclusions, username)) {
                return TRUE;
        }

        if (shell != NULL) {
                char *basename, *nologin_basename, *false_basename;

#ifdef HAVE_GETUSERSHELL
                char *valid_shell;

                ret = TRUE;
                setusershell ();
                while ((valid_shell = getusershell ()) != NULL) {
                        if (g_strcmp0 (shell, valid_shell) != 0)
                                continue;
                        ret = FALSE;
                }
                endusershell ();
#endif

                basename = g_path_get_basename (shell);
                nologin_basename = g_path_get_basename (PATH_NOLOGIN);
                false_basename = g_path_get_basename (PATH_FALSE);

                if (shell[0] == '\0') {
                        ret = TRUE;
                } else if (g_strcmp0 (basename, nologin_basename) == 0) {
                        ret = TRUE;
                } else if (g_strcmp0 (basename, false_basename) == 0) {
                        ret = TRUE;
                }

                g_free (basename);
                g_free (nologin_basename);
                g_free (false_basename);
        }

        if (password_hash != NULL) {
                /* skip over the account-is-locked '!' prefix if present */
                if (password_hash[0] == '!')
                    password_hash++;

                if (password_hash[0] != '\0') {
                        /* modern hashes start with "$n$" */
                        if (password_hash[0] == '$') {
                                if (strlen (password_hash) < 4)
                                    ret = TRUE;

                        /* DES crypt is base64 encoded [./A-Za-z0-9]*
                         */
                        } else if (!g_ascii_isalnum (password_hash[0]) &&
                                   password_hash[0] != '.' &&
                                   password_hash[0] != '/') {
                                ret = TRUE;
                        }
                }

        }

        return ret;
}

#else /* ENABLE_USER_HEURISTICS */

static gboolean
user_classify_parse_login_defs_field (const gchar *contents,
                                      const gchar *key,
                                      uid_t       *result)
{
        gsize key_len;
        gint64 value;
        gchar *end;

        key_len = strlen (key);

        for (;;) {
                /* Our key has to be at the start of the line, followed by whitespace */
                if (strncmp (contents, key, key_len) == 0 && g_ascii_isspace (contents[key_len])) {
                        /* Found it.  Move contents past the key itself and break out. */
                        contents += key_len;
                        break;
                }

                /* Didn't find it.  Find the end of the line. */
                contents = strchr (contents, '\n');

                /* EOF? */
                if (!contents) {
                        /* We didn't find the field... */
                        return FALSE;
                }

                /* Start at the beginning of the next line on next iteration. */
                contents++;
        }

        /* 'contents' now points at the whitespace character just after
         * the field name.  strtoll can deal with that.
         */
        value = g_ascii_strtoll (contents, &end, 10);

        if (*end && !g_ascii_isspace (*end)) {
                g_warning ("Trailing junk after '%s' field in login.defs", key);
                return FALSE;
        }

        if (value <= 0 || value >= G_MAXINT32) {
                g_warning ("Value for '%s' field out of range", key);
                return FALSE;
        }

        *result = value;

        return TRUE;
}

static void
user_classify_read_login_defs (uid_t *min_uid,
                               uid_t *max_uid)
{
        GError *error = NULL;
        char *contents;

        if (!g_file_get_contents ("/etc/login.defs", &contents, NULL, &error)) {
                g_warning ("Could not open /etc/login.defs: %s.  Falling back to default human uid range of %d to %d",
                           error->message, (int) *min_uid, (int) *max_uid);
                g_error_free (error);
                return;
        }

        if (!user_classify_parse_login_defs_field (contents, "UID_MIN", min_uid)) {
                g_warning ("Could not find UID_MIN value in login.defs.  Using default of %d", (int) *min_uid);
        }

        if (!user_classify_parse_login_defs_field (contents, "UID_MAX", max_uid)) {
                g_warning ("Could not find UID_MIN value in login.defs.  Using default of %d", (int) *max_uid);
        }

        g_free (contents);
}

static gboolean
user_classify_is_in_human_range (uid_t uid)
{
        static uid_t min_uid = 1000, max_uid = 60000;
        static gboolean initialised;

        if (!initialised) {
                user_classify_read_login_defs (&min_uid, &max_uid);
                initialised = TRUE;
        }

        return min_uid <= uid && uid <= max_uid;
}
#endif /* ENABLE_USER_HEURISTICS */

gboolean
user_classify_is_human (uid_t        uid,
                        const gchar *username,
                        const gchar *shell,
                        const gchar *password_hash)
{
#ifdef ENABLE_USER_HEURISTICS
        return !user_classify_is_excluded_by_heuristics (username, shell, password_hash);
#else
        return user_classify_is_in_human_range (uid);
#endif
}
