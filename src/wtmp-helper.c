/*
 * Copyright (C) 2013 Red Hat, Inc.
 * Copyright (C) 2014 Canonical Limited
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
 * Authors: Ondrej Holy <oholy@redhat.com>
 *          Ryan Lortie <desrt@desrt.ca>
 */

#include "config.h"

#include "wtmp-helper.h"
#include "user.h"

#ifdef HAVE_UTMPX_H

#include <utmpx.h>

typedef struct {
        guint64 frequency;
        gint64 time;
        GList *previous_logins;
} UserAccounting;

typedef struct {
        gchar  *id;
        gint64  login_time;
        gint64  logout_time;
} UserPreviousLogin;

typedef struct {
        GHashTable *login_hash;
        GHashTable *logout_hash;
} WTmpGeneratorState;

static void
user_previous_login_free (UserPreviousLogin *previous_login)
{
        g_free (previous_login->id);
        g_free (previous_login);
}

static gboolean
wtmp_helper_start (void)
{
#if defined(UTXDB_LOG)
                if (setutxdb (UTXDB_LOG, NULL) != 0) {
                        return FALSE;
                }
#elif defined(WTMPX_FILENAME)
                if (utmpxname (WTMPX_FILENAME) != 0) {
                        return FALSE;
                }

                setutxent ();
#else
#error You have utmpx.h, but no known way to use it for wtmp entries
#endif

                return TRUE;
}

struct passwd *
wtmp_helper_entry_generator (GHashTable *users,
                             gpointer   *state)
{
        GHashTable *login_hash, *logout_hash;
        struct utmpx *wtmp_entry;
        GHashTableIter iter;
        gpointer key, value;
        struct passwd *pwent;
        User *user;
        WTmpGeneratorState *state_data;
        GVariantBuilder *builder, *builder2;
        GList *l;

        if (*state == NULL) {
                /* First iteration */

                if (!wtmp_helper_start ()) {
                        return NULL;
                }

                *state = g_new (WTmpGeneratorState, 1);
                state_data = *state;
                state_data->login_hash = g_hash_table_new_full (g_str_hash, g_str_equal, g_free, g_free);
                state_data->logout_hash = g_hash_table_new_full (g_str_hash, g_str_equal, g_free, NULL);
        }

        /* Every iteration */
        state_data = *state;
        login_hash = state_data->login_hash;
        logout_hash = state_data->logout_hash;
        while ((wtmp_entry = getutxent ())) {
                UserAccounting    *accounting;
                UserPreviousLogin *previous_login;

                if (wtmp_entry->ut_type == BOOT_TIME) {
                        /* Set boot time for missing logout records */
                        g_hash_table_iter_init (&iter, logout_hash);
                        while (g_hash_table_iter_next (&iter, &key, &value)) {
                                previous_login = (UserPreviousLogin *) value;

                                if (previous_login->logout_time == 0) {
                                        previous_login->logout_time = wtmp_entry->ut_tv.tv_sec;
                                }
                        }
                        g_hash_table_remove_all (logout_hash);
                } else if (wtmp_entry->ut_type == DEAD_PROCESS) {
                        /* Save corresponding logout time */
                        if (g_hash_table_lookup_extended (logout_hash, wtmp_entry->ut_line, &key, &value)) {
                                previous_login = (UserPreviousLogin *) value;
                                previous_login->logout_time = wtmp_entry->ut_tv.tv_sec;

                                g_hash_table_remove (logout_hash, previous_login->id);
                        }
                }

                if (wtmp_entry->ut_type != USER_PROCESS) {
                        continue;
                }

                if (wtmp_entry->ut_user[0] == 0) {
                        continue;
                }

                pwent = getpwnam (wtmp_entry->ut_user);
                if (pwent == NULL) {
                        continue;
                }

                if (!g_hash_table_lookup_extended (login_hash,
                                                   wtmp_entry->ut_user,
                                                   &key, &value)) {
                        accounting = g_new (UserAccounting, 1);
                        accounting->frequency = 0;
                        accounting->previous_logins = NULL;

                        g_hash_table_insert (login_hash, g_strdup (wtmp_entry->ut_user), accounting);
                } else {
                        accounting = value;
                }

                accounting->frequency++;
                accounting->time = wtmp_entry->ut_tv.tv_sec;

                /* Add zero logout time to change it later on logout record */
                previous_login = g_new (UserPreviousLogin, 1);
                previous_login->id = g_strdup (wtmp_entry->ut_line);
                previous_login->login_time = wtmp_entry->ut_tv.tv_sec;
                previous_login->logout_time = 0;
                accounting->previous_logins = g_list_prepend (accounting->previous_logins, previous_login);

                g_hash_table_insert (logout_hash, g_strdup (wtmp_entry->ut_line), previous_login);

                return pwent;
        }

        /* Last iteration */
        endutxent ();

        g_hash_table_iter_init (&iter, login_hash);
        while (g_hash_table_iter_next (&iter, &key, &value)) {
                UserAccounting    *accounting = (UserAccounting *) value;
                UserPreviousLogin *previous_login;

                user = g_hash_table_lookup (users, key);
                if (user == NULL) {
                        g_list_free_full (accounting->previous_logins, (GDestroyNotify) user_previous_login_free);
                        continue;
                }

                g_object_set (user, "login-frequency", accounting->frequency, NULL);
                g_object_set (user, "login-time", accounting->time, NULL);

                builder = g_variant_builder_new (G_VARIANT_TYPE ("a(xxa{sv})"));
                for (l = g_list_last (accounting->previous_logins); l != NULL; l = l->prev) {
                        previous_login = l->data;

                        builder2 = g_variant_builder_new (G_VARIANT_TYPE ("a{sv}"));
                        g_variant_builder_add (builder2, "{sv}", "type", g_variant_new_string (previous_login->id));
                        g_variant_builder_add (builder, "(xxa{sv})", previous_login->login_time, previous_login->logout_time, builder2);
                        g_variant_builder_unref (builder2);
                }
                g_object_set (user, "login-history", g_variant_new ("a(xxa{sv})", builder), NULL);
                g_variant_builder_unref (builder);
                g_list_free_full (accounting->previous_logins, (GDestroyNotify) user_previous_login_free);

                user_changed (user);
        }

        g_hash_table_unref (login_hash);
        g_hash_table_unref (logout_hash);
        g_free (state_data);
        *state = NULL;
        return NULL;
}

const gchar *
wtmp_helper_get_path_for_monitor (void)
{
#if defined(WTMPX_FILENAME)
        return WTMPX_FILENAME;
#elif defined(__FreeBSD__)
        return "/var/log/utx.log";
#else
#error Do not know which filename to watch for wtmp changes
#endif
}

#else /* HAVE_UTMPX_H */

struct passwd *
wtmp_helper_entry_generator (GHashTable *users,
                             gpointer   *state)
{
        return NULL;
}

const gchar *
wtmp_helper_get_path_for_monitor (void)
{
        return NULL;
}

#endif /* HAVE_UTMPX_H */
