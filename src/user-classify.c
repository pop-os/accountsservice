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
#include <unistd.h>

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

static gboolean
user_classify_is_blacklisted (const char *username)
{
        static GHashTable *exclusions;

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

        return FALSE;
}

#define PATH_NOLOGIN "/sbin/nologin"
#define PATH_FALSE "/bin/false"

#ifdef ENABLE_USER_HEURISTICS
static gboolean
user_classify_is_excluded_by_heuristics (const gchar *username,
                                         const gchar *password_hash)
{
        gboolean ret = FALSE;

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
#endif /* ENABLE_USER_HEURISTICS */

static gboolean
is_invalid_shell (const char *shell)
{
        char *basename, *nologin_basename, *false_basename;
        int ret = FALSE;

#ifdef HAVE_GETUSERSHELL
        /* getusershell returns a whitelist of valid shells.
         * assume the shell is invalid unless there is a match */
        ret = TRUE;
        char *valid_shell;

        setusershell ();
        while ((valid_shell = getusershell ()) != NULL) {
                if (g_strcmp0 (shell, valid_shell) != 0)
                        continue;
                ret = FALSE;
                break;
        }
        endusershell ();
#endif

        /* always check for false and nologin since they are sometimes included by getusershell */
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

        return ret;
}

gboolean
user_classify_is_human (uid_t        uid,
                        const gchar *username,
                        const gchar *shell,
                        const gchar *password_hash)
{
        if (user_classify_is_blacklisted (username))
                return FALSE;

        if (shell != NULL && is_invalid_shell (shell))
                return FALSE;

#ifdef ENABLE_USER_HEURISTICS
        /* only do heuristics on the range 500-1000 to catch one off migration problems in Fedora */
        if (uid >= 500 && uid < MINIMUM_UID) {
                if (!user_classify_is_excluded_by_heuristics (username, password_hash))
                        return TRUE;
        }
#endif

        return uid >= MINIMUM_UID;
}
