/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*-
 *
 * Copyright (C) 2009-2010 Red Hat, Inc.
 * Copyright (c) 2013 Canonical Limited
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
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
 * Written by: Matthias Clasen <mclasen@redhat.com>
 */

#include "config.h"

#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/wait.h>
#include <pwd.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>

#include <glib.h>
#include <glib/gi18n.h>
#include <glib-object.h>
#include <glib/gstdio.h>
#include <gio/gio.h>
#include <polkit/polkit.h>

#include "user-classify.h"
#include "wtmp-helper.h"
#include "daemon.h"
#include "util.h"

#define PATH_PASSWD "/etc/passwd"
#define PATH_SHADOW "/etc/shadow"
#define PATH_GROUP "/etc/group"
#define PATH_GDM_CUSTOM "/etc/gdm/custom.conf"

enum {
        PROP_0,
        PROP_DAEMON_VERSION
};

struct DaemonPrivate {
        GDBusConnection *bus_connection;
        GDBusProxy *bus_proxy;

        GHashTable *users;

        User *autologin;

        GFileMonitor *passwd_monitor;
        GFileMonitor *shadow_monitor;
        GFileMonitor *group_monitor;
        GFileMonitor *gdm_monitor;
        GFileMonitor *wtmp_monitor;

        guint reload_id;
        guint autologin_id;

        PolkitAuthority *authority;
        GHashTable *extension_ifaces;
};

typedef struct passwd * (* EntryGeneratorFunc) (GHashTable *, gpointer *);

static void daemon_accounts_accounts_iface_init (AccountsAccountsIface *iface);

G_DEFINE_TYPE_WITH_CODE (Daemon, daemon, ACCOUNTS_TYPE_ACCOUNTS_SKELETON, G_IMPLEMENT_INTERFACE (ACCOUNTS_TYPE_ACCOUNTS, daemon_accounts_accounts_iface_init));

#define DAEMON_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), TYPE_DAEMON, DaemonPrivate))

static const GDBusErrorEntry accounts_error_entries[] =
{ 
        { ERROR_FAILED, "org.freedesktop.Accounts.Error.Failed" },
        { ERROR_USER_EXISTS, "org.freedesktop.Accounts.Error.UserExists" },
        { ERROR_USER_DOES_NOT_EXIST, "org.freedesktop.Accounts.Error.UserDoesNotExist" },
        { ERROR_PERMISSION_DENIED, "org.freedesktop.Accounts.Error.PermissionDenied" },
        { ERROR_NOT_SUPPORTED, "org.freedesktop.Accounts.Error.NotSupported" }
};

GQuark
error_quark (void)
{
        static volatile gsize quark_volatile = 0;

        g_dbus_error_register_error_domain ("accounts_error",
                                            &quark_volatile,
                                            accounts_error_entries,
                                            G_N_ELEMENTS (accounts_error_entries));

        return (GQuark) quark_volatile;
}
#define ENUM_ENTRY(NAME, DESC) { NAME, "" #NAME "", DESC }

GType
error_get_type (void)
{
  static GType etype = 0;

  if (etype == 0)
    {
      static const GEnumValue values[] =
        {
          ENUM_ENTRY (ERROR_FAILED, "Failed"),
          ENUM_ENTRY (ERROR_USER_EXISTS, "UserExists"),
          ENUM_ENTRY (ERROR_USER_DOES_NOT_EXIST, "UserDoesntExist"),
          ENUM_ENTRY (ERROR_PERMISSION_DENIED, "PermissionDenied"),
          ENUM_ENTRY (ERROR_NOT_SUPPORTED, "NotSupported"),
          { 0, 0, 0 }
        };
      g_assert (NUM_ERRORS == G_N_ELEMENTS (values) - 1);
      etype = g_enum_register_static ("Error", values);
    }
  return etype;
}

#ifndef HAVE_FGETPWENT
#include "fgetpwent.c"
#endif

static struct passwd *
entry_generator_fgetpwent (GHashTable *users,
                           gpointer   *state)
{
        struct passwd *pwent;
        FILE *fp;

        /* First iteration */
        if (*state == NULL) {
                *state = fp = fopen (PATH_PASSWD, "r");
                if (fp == NULL) {
                        g_warning ("Unable to open %s: %s", PATH_PASSWD, g_strerror (errno));
                        return NULL;
                }
        }

        /* Every iteration */
        fp = *state;
        pwent = fgetpwent (fp);
        if (pwent != NULL) {
                return pwent;
        }

        /* Last iteration */
        fclose (fp);
        *state = NULL;
        return NULL;
}

static struct passwd *
entry_generator_cachedir (GHashTable *users,
                          gpointer   *state)
{
        struct passwd *pwent;
        const gchar *name;
        GError *error = NULL;
        gchar *filename;
        gboolean regular;
        GHashTableIter iter;
        GKeyFile *key_file;
        User *user;
        GDir *dir;

        /* First iteration */
        if (*state == NULL) {
                *state = g_dir_open (USERDIR, 0, &error);
                if (error != NULL) {
                        if (!g_error_matches (error, G_FILE_ERROR, G_FILE_ERROR_NOENT))
                                g_warning ("couldn't list user cache directory: %s", USERDIR);
                        g_error_free (error);
                        return NULL;
                }
        }

        /* Every iteration */

        /*
         * Use names of files of regular type to lookup information
         * about each user. Loop until we find something valid.
         */
        dir = *state;
        while (TRUE) {
                name = g_dir_read_name (dir);
                if (name == NULL)
                        break;

                /* Only load files in this directory */
                filename = g_build_filename (USERDIR, name, NULL);
                regular = g_file_test (filename, G_FILE_TEST_IS_REGULAR);
                g_free (filename);

                if (regular) {
                        pwent = getpwnam (name);
                        if (pwent == NULL)
                                g_debug ("user '%s' in cache dir but not present on system", name);
                        else
                                return pwent;
                }
        }

        /* Last iteration */
        g_dir_close (dir);

        /* Update all the users from the files in the cache dir */
        g_hash_table_iter_init (&iter, users);
        while (g_hash_table_iter_next (&iter, (gpointer *)&name, (gpointer *)&user)) {
                filename = g_build_filename (USERDIR, name, NULL);
                key_file = g_key_file_new ();
                if (g_key_file_load_from_file (key_file, filename, 0, NULL))
                        user_update_from_keyfile (user, key_file);
                g_key_file_unref (key_file);
                g_free (filename);
        }

        *state = NULL;
        return NULL;
}

static void
load_entries (Daemon             *daemon,
              GHashTable         *users,
              EntryGeneratorFunc  entry_generator)
{
        gpointer generator_state = NULL;
        struct passwd *pwent;
        User *user = NULL;

        g_assert (entry_generator != NULL);

        for (;;) {
                pwent = entry_generator (users, &generator_state);
                if (pwent == NULL)
                        break;

                /* Skip system users... */
                if (!user_classify_is_human (pwent->pw_uid, pwent->pw_name, pwent->pw_shell, NULL)) {
                        g_debug ("skipping user: %s", pwent->pw_name);
                        continue;
                }

                /* ignore duplicate entries */
                if (g_hash_table_lookup (users, pwent->pw_name)) {
                        continue;
                }

                user = g_hash_table_lookup (daemon->priv->users, pwent->pw_name);
                if (user == NULL) {
                        user = user_new (daemon, pwent->pw_uid);
                } else {
                        g_object_ref (user);
                }

                /* freeze & update users not already in the new list */
                g_object_freeze_notify (G_OBJECT (user));
                user_update_from_pwent (user, pwent);

                g_hash_table_insert (users, g_strdup (user_get_user_name (user)), user);
                g_debug ("loaded user: %s", user_get_user_name (user));
        }

        /* Generator should have cleaned up */
        g_assert (generator_state == NULL);
}

static GHashTable *
create_users_hash_table (void)
{
        return g_hash_table_new_full (g_str_hash,
                                      g_str_equal,
                                      g_free,
                                      g_object_unref);
}

static void
reload_users (Daemon *daemon)
{
        GHashTable *users;
        GHashTable *old_users;
        GHashTable *local;
        GHashTableIter iter;
        gpointer name;
        User *user;

        /* Track the users that we saw during our (re)load */
        users = create_users_hash_table ();

        /*
         * NOTE: As we load data from all the sources, notifies are
         * frozen in load_entries() and then thawed as we process
         * them below.
         */

        /* Load the local users into our hash table */
        load_entries (daemon, users, entry_generator_fgetpwent);
        local = g_hash_table_new (g_str_hash, g_str_equal);
        g_hash_table_iter_init (&iter, users);
        while (g_hash_table_iter_next (&iter, &name, NULL))
                g_hash_table_add (local, name);

        /* Now add/update users from other sources, possibly non-local */
        load_entries (daemon, users, wtmp_helper_entry_generator);
        load_entries (daemon, users, entry_generator_cachedir);

        /* Mark which users are local, which are not */
        g_hash_table_iter_init (&iter, users);
        while (g_hash_table_iter_next (&iter, &name, (gpointer *)&user))
                user_update_local_account_property (user, g_hash_table_lookup (local, name) != NULL);

        g_hash_table_destroy (local);

        /* Swap out the users */
        old_users = daemon->priv->users;
        daemon->priv->users = users;

        /* Remove all the old users */
        g_hash_table_iter_init (&iter, old_users);
        while (g_hash_table_iter_next (&iter, &name, (gpointer *)&user)) {
                if (!g_hash_table_lookup (users, name)) {
                        user_unregister (user);
                        accounts_accounts_emit_user_deleted (ACCOUNTS_ACCOUNTS (daemon),
                                                             user_get_object_path (user));
                }
        }

        /* Register all the new users */
        g_hash_table_iter_init (&iter, users);
        while (g_hash_table_iter_next (&iter, &name, (gpointer *)&user)) {
                if (!g_hash_table_lookup (old_users, name)) {
                        user_register (user);
                        accounts_accounts_emit_user_added (ACCOUNTS_ACCOUNTS (daemon),
                                                           user_get_object_path (user));
                }
                g_object_thaw_notify (G_OBJECT (user));
        }

        g_hash_table_destroy (old_users);
}

static gboolean
reload_users_timeout (Daemon *daemon)
{
        reload_users (daemon);
        daemon->priv->reload_id = 0;

        return FALSE;
}

static gboolean load_autologin (Daemon    *daemon,
                                gchar    **name,
                                gboolean  *enabled,
                                GError   **error);

static gboolean
reload_autologin_timeout (Daemon *daemon)
{
        gboolean enabled;
        gchar *name = NULL;
        GError *error = NULL;
        User *user = NULL;

        daemon->priv->autologin_id = 0;

        if (!load_autologin (daemon, &name, &enabled, &error)) {
                g_debug ("failed to load gdms custom.conf: %s", error->message);
                g_error_free (error);
                g_free (name);

                return FALSE;
        }

        if (enabled && name)
                user = daemon_local_find_user_by_name (daemon, name);

        if (daemon->priv->autologin != NULL && daemon->priv->autologin != user) {
                g_object_set (daemon->priv->autologin, "automatic-login", FALSE, NULL);
                g_signal_emit_by_name (daemon->priv->autologin, "changed", 0);
                g_object_unref (daemon->priv->autologin);
                daemon->priv->autologin = NULL;
        }

        if (enabled) {
                g_debug ("automatic login is enabled for '%s'", name);
                if (daemon->priv->autologin != user) {
                        g_object_set (user, "automatic-login", TRUE, NULL);
                        daemon->priv->autologin = g_object_ref (user);
                        g_signal_emit_by_name (daemon->priv->autologin, "changed", 0);
                }
        }
        else {
                g_debug ("automatic login is disabled");
        }

        g_free (name);

        return FALSE;
}

static void
queue_reload_users_soon (Daemon *daemon)
{
        if (daemon->priv->reload_id > 0) {
                return;
        }

        /* we wait half a second or so in case /etc/passwd and
         * /etc/shadow are changed at the same time, or repeatedly.
         */
        daemon->priv->reload_id = g_timeout_add (500, (GSourceFunc)reload_users_timeout, daemon);
}

static void
queue_reload_users (Daemon *daemon)
{
        if (daemon->priv->reload_id > 0) {
                return;
        }

        daemon->priv->reload_id = g_idle_add ((GSourceFunc)reload_users_timeout, daemon);
}

static void
queue_reload_autologin (Daemon *daemon)
{
        if (daemon->priv->autologin_id > 0) {
                return;
        }

        daemon->priv->autologin_id = g_idle_add ((GSourceFunc)reload_autologin_timeout, daemon);
}

static void
on_users_monitor_changed (GFileMonitor      *monitor,
                          GFile             *file,
                          GFile             *other_file,
                          GFileMonitorEvent  event_type,
                          Daemon            *daemon)
{
        if (event_type != G_FILE_MONITOR_EVENT_CHANGED &&
            event_type != G_FILE_MONITOR_EVENT_CREATED) {
                return;
        }

        queue_reload_users_soon (daemon);
}

static void
on_gdm_monitor_changed (GFileMonitor      *monitor,
                        GFile             *file,
                        GFile             *other_file,
                        GFileMonitorEvent  event_type,
                        Daemon            *daemon)
{
        if (event_type != G_FILE_MONITOR_EVENT_CHANGED &&
            event_type != G_FILE_MONITOR_EVENT_CREATED) {
                return;
        }

        queue_reload_autologin (daemon);
}

typedef void FileChangeCallback (GFileMonitor      *monitor,
                                 GFile             *file,
                                 GFile             *other_file,
                                 GFileMonitorEvent  event_type,
                                 Daemon            *daemon);

static GFileMonitor *
setup_monitor (Daemon             *daemon,
               const gchar        *path,
               FileChangeCallback *callback)
{
        GError *error = NULL;
        GFile *file;
        GFileMonitor *monitor;

        if (!path) {
                return NULL;
        }

        file = g_file_new_for_path (path);
        monitor = g_file_monitor_file (file,
                                       G_FILE_MONITOR_NONE,
                                       NULL,
                                       &error);
        if (monitor != NULL) {
                g_signal_connect (monitor,
                                  "changed",
                                  G_CALLBACK (callback),
                                  daemon);
        } else {
                g_warning ("Unable to monitor %s: %s", path, error->message);
                g_error_free (error);
        }
        g_object_unref (file);

        return monitor;
}

static void
daemon_init (Daemon *daemon)
{
        daemon->priv = DAEMON_GET_PRIVATE (daemon);

        daemon->priv->extension_ifaces = daemon_read_extension_ifaces ();

        daemon->priv->users = create_users_hash_table ();

        daemon->priv->passwd_monitor = setup_monitor (daemon,
                                                      PATH_PASSWD,
                                                      on_users_monitor_changed);
        daemon->priv->shadow_monitor = setup_monitor (daemon,
                                                      PATH_SHADOW,
                                                      on_users_monitor_changed);
        daemon->priv->group_monitor = setup_monitor (daemon,
                                                     PATH_GROUP,
                                                     on_users_monitor_changed);

        daemon->priv->wtmp_monitor = setup_monitor (daemon,
                                                    wtmp_helper_get_path_for_monitor (),
                                                    on_users_monitor_changed);

        daemon->priv->gdm_monitor = setup_monitor (daemon,
                                                   PATH_GDM_CUSTOM,
                                                   on_gdm_monitor_changed);
        reload_users_timeout (daemon);
        queue_reload_autologin (daemon);
}

static void
daemon_finalize (GObject *object)
{
        Daemon *daemon;

        g_return_if_fail (IS_DAEMON (object));

        daemon = DAEMON (object);

        if (daemon->priv->bus_proxy != NULL)
                g_object_unref (daemon->priv->bus_proxy);

        if (daemon->priv->bus_connection != NULL)
                g_object_unref (daemon->priv->bus_connection);

        g_hash_table_destroy (daemon->priv->users);

        g_hash_table_unref (daemon->priv->extension_ifaces);

        G_OBJECT_CLASS (daemon_parent_class)->finalize (object);
}

static gboolean
register_accounts_daemon (Daemon *daemon)
{
        GError *error = NULL;

        daemon->priv->authority = polkit_authority_get_sync (NULL, &error);

        if (daemon->priv->authority == NULL) {
                if (error != NULL) {
                        g_critical ("error getting polkit authority: %s", error->message);
                        g_error_free (error);
                }
                goto error;
        }

        daemon->priv->bus_connection = g_bus_get_sync (G_BUS_TYPE_SYSTEM, NULL, &error);
        if (daemon->priv->bus_connection == NULL) {
                if (error != NULL) {
                        g_critical ("error getting system bus: %s", error->message);
                        g_error_free (error);
                }
                goto error;
        }

        if (!g_dbus_interface_skeleton_export (G_DBUS_INTERFACE_SKELETON (daemon),
                                               daemon->priv->bus_connection,
                                               "/org/freedesktop/Accounts",
                                               &error)) {
                if (error != NULL) {
                        g_critical ("error exporting interface: %s", error->message);
                        g_error_free (error);
                }
                goto error;     
        }

        return TRUE;

 error:
        return FALSE;
}

Daemon *
daemon_new (void)
{
        Daemon *daemon;

        daemon = DAEMON (g_object_new (TYPE_DAEMON, NULL));

        if (!register_accounts_daemon (DAEMON (daemon))) {
                g_object_unref (daemon);
                goto error;
        }

        return daemon;

 error:
        return NULL;
}

static void
throw_error (GDBusMethodInvocation *context,
             gint                   error_code,
             const gchar           *format,
             ...)
{
        va_list args;
        gchar *message;

        va_start (args, format);
        message = g_strdup_vprintf (format, args);
        va_end (args);

        g_dbus_method_invocation_return_error (context, ERROR, error_code, "%s", message);

        g_free (message);
}

static User *
add_new_user_for_pwent (Daemon        *daemon,
                        struct passwd *pwent)
{
        User *user;

        user = user_new (daemon, pwent->pw_uid);
        user_update_from_pwent (user, pwent);
        user_register (user);

        g_hash_table_insert (daemon->priv->users,
                             g_strdup (user_get_user_name (user)),
                             user);

        accounts_accounts_emit_user_added (ACCOUNTS_ACCOUNTS (daemon), user_get_object_path (user));

        return user;
}

User *
daemon_local_find_user_by_id (Daemon *daemon,
                              uid_t   uid)
{
        User *user;
        struct passwd *pwent;

        pwent = getpwuid (uid);
        if (pwent == NULL) {
                g_debug ("unable to lookup uid %d", (int)uid);
                return NULL;
        }

        user = g_hash_table_lookup (daemon->priv->users, pwent->pw_name);

        if (user == NULL)
                user = add_new_user_for_pwent (daemon, pwent);

        return user;
}

User *
daemon_local_find_user_by_name (Daemon      *daemon,
                                const gchar *name)
{
        User *user;
        struct passwd *pwent;

        pwent = getpwnam (name);
        if (pwent == NULL) {
                g_debug ("unable to lookup name %s: %s", name, g_strerror (errno));
                return NULL;
        }

        user = g_hash_table_lookup (daemon->priv->users, pwent->pw_name);

        if (user == NULL)
                user = add_new_user_for_pwent (daemon, pwent);

        return user;
}

User *
daemon_local_get_automatic_login_user (Daemon *daemon)
{
        return daemon->priv->autologin;
}

static gboolean
daemon_find_user_by_id (AccountsAccounts      *accounts,
                        GDBusMethodInvocation *context,
                        gint64                 uid)
{
        Daemon *daemon = (Daemon*)accounts;
        User *user;

        user = daemon_local_find_user_by_id (daemon, uid);

        if (user) {
                accounts_accounts_complete_find_user_by_id (NULL, context, user_get_object_path (user));
        }
        else {
                throw_error (context, ERROR_FAILED, "Failed to look up user with uid %d.", (int)uid);
        }

        return TRUE;
}

static gboolean
daemon_find_user_by_name (AccountsAccounts      *accounts,
                          GDBusMethodInvocation *context,
                          const gchar           *name)
{
        Daemon *daemon = (Daemon*)accounts;
        User *user;

        user = daemon_local_find_user_by_name (daemon, name);

        if (user) {
                accounts_accounts_complete_find_user_by_name (NULL, context, user_get_object_path (user));
        }
        else {
                throw_error (context, ERROR_FAILED, "Failed to look up user with name %s.", name);
        }

        return TRUE;
}

typedef struct {
        Daemon *daemon;
        GDBusMethodInvocation *context;
} ListUserData;


static ListUserData *
list_user_data_new (Daemon                *daemon,
                    GDBusMethodInvocation *context)
{
        ListUserData *data;

        data = g_new0 (ListUserData, 1);

        data->daemon = g_object_ref (daemon);
        data->context = context;

        return data;
}

static void
list_user_data_free (ListUserData *data)
{
        g_object_unref (data->daemon);
        g_free (data);
}

static gboolean
finish_list_cached_users (gpointer user_data)
{
        ListUserData *data = user_data;
        GPtrArray *object_paths;
        GHashTableIter iter;
        const gchar *name;
        User *user;
        uid_t uid;
        const gchar *shell;

        object_paths = g_ptr_array_new ();

        g_hash_table_iter_init (&iter, data->daemon->priv->users);
        while (g_hash_table_iter_next (&iter, (gpointer *)&name, (gpointer *)&user)) {
                uid = user_get_uid (user);
                shell = user_get_shell (user);

                if (!user_classify_is_human (uid, name, shell, NULL)) {
                        g_debug ("user %s %ld excluded", name, (long) uid);
                        continue;
                }

                g_debug ("user %s %ld not excluded", name, (long) uid);
                g_ptr_array_add (object_paths, (gpointer) user_get_object_path (user));
        }
        g_ptr_array_add (object_paths, NULL);

        accounts_accounts_complete_list_cached_users (NULL, data->context, (const gchar * const *) object_paths->pdata);

        g_ptr_array_free (object_paths, TRUE);

        list_user_data_free (data);

        return FALSE;
}

static gboolean
daemon_list_cached_users (AccountsAccounts      *accounts,
                          GDBusMethodInvocation *context)
{
        Daemon *daemon = (Daemon*)accounts;
        ListUserData *data;

        data = list_user_data_new (daemon, context);

        if (daemon->priv->reload_id > 0) {
                /* reload in progress, wait a bit */
                g_idle_add (finish_list_cached_users, data);
        }
        else {
                finish_list_cached_users (data);
        }

        return TRUE;
}

static const gchar *
daemon_get_daemon_version (AccountsAccounts *object)
{
    return VERSION;
}

static void
cache_user (Daemon *daemon,
            User   *user)
{
        gchar       *filename;
        const char  *user_name;

        /* Always use the canonical user name looked up */
        user_name = user_get_user_name (user);

        filename = g_build_filename (USERDIR, user_name, NULL);
        if (!g_file_test (filename, G_FILE_TEST_EXISTS)) {
                user_save (user);
        }

        g_free (filename);
}

typedef struct {
        gchar *user_name;
        gchar *real_name;
        gint account_type;
} CreateUserData;

static void
create_data_free (gpointer data)
{
        CreateUserData *cd = data;

        g_free (cd->user_name);
        g_free (cd->real_name);
        g_free (cd);
}

static void
daemon_create_user_authorized_cb (Daemon                *daemon,
                                  User                  *dummy,
                                  GDBusMethodInvocation *context,
                                  gpointer               data)

{
        CreateUserData *cd = data;
        User *user;
        GError *error;
        const gchar *argv[9];

        if (getpwnam (cd->user_name) != NULL) {
                throw_error (context, ERROR_USER_EXISTS, "A user with name '%s' already exists", cd->user_name);

                return;
        }

        sys_log (context, "create user '%s'", cd->user_name);

        argv[0] = "/usr/sbin/useradd";
        argv[1] = "-m";
        argv[2] = "-c";
        argv[3] = cd->real_name;
        if (cd->account_type == ACCOUNT_TYPE_ADMINISTRATOR) {
                argv[4] = "-G";
                argv[5] = ADMIN_GROUP;
                argv[6] = "--";
                argv[7] = cd->user_name;
                argv[8] = NULL;
        }
        else if (cd->account_type == ACCOUNT_TYPE_STANDARD) {
                argv[4] = "--";
                argv[5] = cd->user_name;
                argv[6] = NULL;
        }
        else {
                throw_error (context, ERROR_FAILED, "Don't know how to add user of type %d", cd->account_type);
                return;
        }

        error = NULL;
        if (!spawn_with_login_uid (context, argv, &error)) {
                throw_error (context, ERROR_FAILED, "running '%s' failed: %s", argv[0], error->message);
                g_error_free (error);
                return;
        }

        user = daemon_local_find_user_by_name (daemon, cd->user_name);
        user_update_local_account_property (user, TRUE);
        user_update_system_account_property (user, FALSE);

        cache_user (daemon, user);

        accounts_accounts_complete_create_user (NULL, context, user_get_object_path (user));
}

static gboolean
daemon_create_user (AccountsAccounts      *accounts,
                    GDBusMethodInvocation *context,
                    const gchar           *user_name,
                    const gchar           *real_name,
                    gint                   account_type)
{
        Daemon *daemon = (Daemon*)accounts;
        CreateUserData *data;

        data = g_new0 (CreateUserData, 1);
        data->user_name = g_strdup (user_name);
        data->real_name = g_strdup (real_name);
        data->account_type = account_type;

        daemon_local_check_auth (daemon,
                                 NULL,
                                 "org.freedesktop.accounts.user-administration",
                                 TRUE,
                                 daemon_create_user_authorized_cb,
                                 context,
                                 data,
                                 (GDestroyNotify)create_data_free);

        return TRUE;
}

static void
daemon_cache_user_authorized_cb (Daemon                *daemon,
                                 User                  *dummy,
                                 GDBusMethodInvocation *context,
                                 gpointer               data)
{
        const gchar *user_name = data;
        User        *user;

        sys_log (context, "cache user '%s'", user_name);

        user = daemon_local_find_user_by_name (daemon, user_name);
        if (user == NULL) {
                throw_error (context, ERROR_USER_DOES_NOT_EXIST,
                             "No user with the name %s found", user_name);
                return;
        }

        user_update_system_account_property (user, FALSE);

        cache_user (daemon, user);

        accounts_accounts_complete_cache_user (NULL, context, user_get_object_path (user));
}

static gboolean
daemon_cache_user (AccountsAccounts      *accounts,
                   GDBusMethodInvocation *context,
                   const gchar           *user_name)
{
        Daemon *daemon = (Daemon*)accounts;

        /* Can't have a slash in the user name */
        if (strchr (user_name, '/') != NULL) {
                g_dbus_method_invocation_return_error (context, G_DBUS_ERROR,
                                                       G_DBUS_ERROR_INVALID_ARGS,
                                                       "Invalid user name: %s", user_name);
                return TRUE;
        }

        daemon_local_check_auth (daemon,
                                 NULL,
                                 "org.freedesktop.accounts.user-administration",
                                 TRUE,
                                 daemon_cache_user_authorized_cb,
                                 context,
                                 g_strdup (user_name),
                                 g_free);

        return TRUE;
}

static void
daemon_uncache_user_authorized_cb (Daemon                *daemon,
                                   User                  *dummy,
                                   GDBusMethodInvocation *context,
                                   gpointer               data)
{
        const gchar *user_name = data;
        gchar       *filename;
        User        *user;

        sys_log (context, "uncache user '%s'", user_name);

        user = daemon_local_find_user_by_name (daemon, user_name);
        if (user == NULL) {
                throw_error (context, ERROR_USER_DOES_NOT_EXIST,
                             "No user with the name %s found", user_name);
                return;
        }

        /* Always use the canonical user name looked up */
        user_name = user_get_user_name (user);

        filename = g_build_filename (USERDIR, user_name, NULL);
        g_remove (filename);
        g_free (filename);

        filename = g_build_filename (ICONDIR, user_name, NULL);
        g_remove (filename);
        g_free (filename);

        accounts_accounts_complete_uncache_user (NULL, context);

        queue_reload_users (daemon);
}

static gboolean
daemon_uncache_user (AccountsAccounts      *accounts,
                     GDBusMethodInvocation *context,
                     const gchar           *user_name)
{
        Daemon *daemon = (Daemon*)accounts;

        daemon_local_check_auth (daemon,
                                 NULL,
                                 "org.freedesktop.accounts.user-administration",
                                 TRUE,
                                 daemon_uncache_user_authorized_cb,
                                 context,
                                 g_strdup (user_name),
                                 g_free);

        return TRUE;
}

typedef struct {
        uid_t uid;
        gboolean remove_files;
} DeleteUserData;

static void
daemon_delete_user_authorized_cb (Daemon                *daemon,
                                  User                  *dummy,
                                  GDBusMethodInvocation *context,
                                  gpointer               data)

{
        DeleteUserData *ud = data;
        GError *error;
        gchar *filename;
        struct passwd *pwent;
        const gchar *argv[6];

        pwent = getpwuid (ud->uid);

        if (pwent == NULL) {
                throw_error (context, ERROR_USER_DOES_NOT_EXIST, "No user with uid %d found", ud->uid);

                return;
        }

        sys_log (context, "delete user '%s' (%d)", pwent->pw_name, ud->uid);

        if (daemon->priv->autologin != NULL) {
                User *user;

                user = daemon_local_find_user_by_id (daemon, ud->uid);

                g_assert (user != NULL);

                if (daemon->priv->autologin == user) {
                        daemon_local_set_automatic_login (daemon, user, FALSE, NULL);
                }

        }

        filename = g_build_filename (USERDIR, pwent->pw_name, NULL);
        g_remove (filename);
        g_free (filename);

        filename = g_build_filename (ICONDIR, pwent->pw_name, NULL);
        g_remove (filename);
        g_free (filename);

        argv[0] = "/usr/sbin/userdel";
        if (ud->remove_files) {
                argv[1] = "-f";
                argv[2] = "-r";
                argv[3] = "--";
                argv[4] = pwent->pw_name;
                argv[5] = NULL;
        }
        else {
                argv[1] = "-f";
                argv[2] = "--";
                argv[3] = pwent->pw_name;
                argv[4] = NULL;
        }

        error = NULL;
        if (!spawn_with_login_uid (context, argv, &error)) {
                throw_error (context, ERROR_FAILED, "running '%s' failed: %s", argv[0], error->message);
                g_error_free (error);
                return;
        }

        accounts_accounts_complete_delete_user (NULL, context);
}


static gboolean
daemon_delete_user (AccountsAccounts      *accounts,
                    GDBusMethodInvocation *context,
                    gint64                 uid,
                    gboolean               remove_files)
{
        Daemon *daemon = (Daemon*)accounts;
        DeleteUserData *data;

        if ((uid_t)uid == 0) {
                throw_error (context, ERROR_FAILED, "Refuse to delete root user");
                return TRUE;
        }

        data = g_new0 (DeleteUserData, 1);
        data->uid = (uid_t)uid;
        data->remove_files = remove_files;

        daemon_local_check_auth (daemon,
                                 NULL,
                                 "org.freedesktop.accounts.user-administration",
                                 TRUE,
                                 daemon_delete_user_authorized_cb,
                                 context,
                                 data,
                                 (GDestroyNotify)g_free);

        return TRUE;
}

typedef struct {
        Daemon *daemon;
        User *user;
        AuthorizedCallback authorized_cb;
        GDBusMethodInvocation *context;
        gpointer data;
        GDestroyNotify destroy_notify;
} CheckAuthData;

static void
check_auth_data_free (CheckAuthData *data)
{
        g_object_unref (data->daemon);

        if (data->user)
                g_object_unref (data->user);

        if (data->destroy_notify)
                (*data->destroy_notify) (data->data);

        g_free (data);
}

static void
check_auth_cb (PolkitAuthority *authority,
               GAsyncResult    *res,
               gpointer         data)
{
        CheckAuthData *cad = data;
        PolkitAuthorizationResult *result;
        GError *error;
        gboolean is_authorized;

        is_authorized = FALSE;

        error = NULL;
        result = polkit_authority_check_authorization_finish (authority, res, &error);
        if (error) {
                throw_error (cad->context, ERROR_PERMISSION_DENIED, "Not authorized: %s", error->message);
                g_error_free (error);
        }
        else {
                if (polkit_authorization_result_get_is_authorized (result)) {
                        is_authorized = TRUE;
                }
                else if (polkit_authorization_result_get_is_challenge (result)) {
                        throw_error (cad->context, ERROR_PERMISSION_DENIED, "Authentication is required");
                }
                else {
                        throw_error (cad->context, ERROR_PERMISSION_DENIED, "Not authorized");
                }

                g_object_unref (result);
        }

        if (is_authorized) {
                (* cad->authorized_cb) (cad->daemon,
                                        cad->user,
                                        cad->context,
                                        cad->data);
        }

        check_auth_data_free (data);
}

void
daemon_local_check_auth (Daemon                *daemon,
                         User                  *user,
                         const gchar           *action_id,
                         gboolean               allow_interaction,
                         AuthorizedCallback     authorized_cb,
                         GDBusMethodInvocation *context,
                         gpointer               authorized_cb_data,
                         GDestroyNotify         destroy_notify)
{
        CheckAuthData *data;
        PolkitSubject *subject;
        PolkitCheckAuthorizationFlags flags;

        data = g_new0 (CheckAuthData, 1);
        data->daemon = g_object_ref (daemon);
        if (user)
                data->user = g_object_ref (user);
        data->context = context;
        data->authorized_cb = authorized_cb;
        data->data = authorized_cb_data;
        data->destroy_notify = destroy_notify;

        subject = polkit_system_bus_name_new (g_dbus_method_invocation_get_sender (context));

        flags = POLKIT_CHECK_AUTHORIZATION_FLAGS_NONE;
        if (allow_interaction)
                flags |= POLKIT_CHECK_AUTHORIZATION_FLAGS_ALLOW_USER_INTERACTION;
        polkit_authority_check_authorization (daemon->priv->authority,
                                              subject,
                                              action_id,
                                              NULL,
                                              flags,
                                              NULL,
                                              (GAsyncReadyCallback) check_auth_cb,
                                              data);

        g_object_unref (subject);
}

gboolean
load_autologin (Daemon      *daemon,
                gchar      **name,
                gboolean    *enabled,
                GError     **error)
{
        GKeyFile *keyfile;
        GError *local_error;
        gchar *string;

        keyfile = g_key_file_new ();
        if (!g_key_file_load_from_file (keyfile,
                                        PATH_GDM_CUSTOM,
                                        G_KEY_FILE_KEEP_COMMENTS,
                                        error)) {
                g_key_file_free (keyfile);
                return FALSE;
        }

        local_error = NULL;
        string = g_key_file_get_string (keyfile, "daemon", "AutomaticLoginEnable", &local_error);
        if (local_error) {
                g_propagate_error (error, local_error);
                g_key_file_free (keyfile);
                g_free (string);
                return FALSE;
        }
        if (string != NULL && (g_ascii_strcasecmp (string, "true") == 0 || strcmp (string, "1") == 0)) {
                *enabled = TRUE;
        }
        else {
                *enabled = FALSE;
        }
        g_free (string);

        *name = g_key_file_get_string (keyfile, "daemon", "AutomaticLogin", &local_error);
        if (local_error) {
                g_propagate_error (error, local_error);
                g_key_file_free (keyfile);
                return FALSE;
        }

        g_key_file_free (keyfile);

        return TRUE;
}

static gboolean
save_autologin (Daemon      *daemon,
                const gchar *name,
                gboolean     enabled,
                GError     **error)
{
        GKeyFile *keyfile;
        gchar *data;
        gboolean result;

        keyfile = g_key_file_new ();
        if (!g_key_file_load_from_file (keyfile,
                                        PATH_GDM_CUSTOM,
                                        G_KEY_FILE_KEEP_COMMENTS,
                                        error)) {
                g_key_file_free (keyfile);
                return FALSE;
        }

        g_key_file_set_string (keyfile, "daemon", "AutomaticLoginEnable", enabled ? "True" : "False");
        g_key_file_set_string (keyfile, "daemon", "AutomaticLogin", name);

        data = g_key_file_to_data (keyfile, NULL, NULL);
        result = g_file_set_contents (PATH_GDM_CUSTOM, data, -1, error);

        g_key_file_free (keyfile);
        g_free (data);

        return result;
}

gboolean
daemon_local_set_automatic_login (Daemon    *daemon,
                                  User      *user,
                                  gboolean   enabled,
                                  GError   **error)
{
        if (daemon->priv->autologin == user && enabled) {
                return TRUE;
        }

        if (daemon->priv->autologin != user && !enabled) {
                return TRUE;
        }

        if (!save_autologin (daemon, user_get_user_name (user), enabled, error)) {
                return FALSE;
        }

        if (daemon->priv->autologin != NULL) {
                g_object_set (daemon->priv->autologin, "automatic-login", FALSE, NULL);
                g_signal_emit_by_name (daemon->priv->autologin, "changed", 0);
                g_object_unref (daemon->priv->autologin);
                daemon->priv->autologin = NULL;
        }

        if (enabled) {
                g_object_set (user, "automatic-login", TRUE, NULL);
                g_signal_emit_by_name (user, "changed", 0);
                g_object_ref (user);
                daemon->priv->autologin = user;
        }

        return TRUE;
}

GHashTable *
daemon_get_extension_ifaces (Daemon *daemon)
{
  return daemon->priv->extension_ifaces;
}

static void
get_property (GObject    *object,
              guint       prop_id,
              GValue     *value,
              GParamSpec *pspec)
{
       switch (prop_id) {
        case PROP_DAEMON_VERSION:
                g_value_set_string (value, VERSION);
                break;

        default:
                G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
                break;
        }
}

static void
set_property (GObject      *object,
              guint         prop_id,
              const GValue *value,
              GParamSpec   *pspec)
{
       switch (prop_id) {
        case PROP_DAEMON_VERSION:
                g_assert_not_reached ();
                break;

        default:
                G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
                break;
        }
}

static void
daemon_class_init (DaemonClass *klass)
{
        GObjectClass *object_class = G_OBJECT_CLASS (klass);

        object_class->finalize = daemon_finalize;
        object_class->get_property = get_property;
        object_class->set_property = set_property;

        g_type_class_add_private (klass, sizeof (DaemonPrivate));

        g_object_class_override_property (object_class,
                                          PROP_DAEMON_VERSION,
                                          "daemon-version");
}

static void
daemon_accounts_accounts_iface_init (AccountsAccountsIface *iface)
{
        iface->handle_create_user = daemon_create_user;
        iface->handle_delete_user = daemon_delete_user;
        iface->handle_find_user_by_id = daemon_find_user_by_id;
        iface->handle_find_user_by_name = daemon_find_user_by_name;
        iface->handle_list_cached_users = daemon_list_cached_users;
        iface->get_daemon_version = daemon_get_daemon_version;
        iface->handle_cache_user = daemon_cache_user;
        iface->handle_uncache_user = daemon_uncache_user;
}
