/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*-
  *
  * Copyright (C) 2004-2005 James M. Cape <jcape@ignore-your.tv>.
  * Copyright (C) 2007-2008 William Jon McCann <mccann@jhu.edu>
  * Copyright (C) 2009-2010 Red Hat, Inc.
  * Copyright © 2013 Canonical Limited
  *
  * This program is free software; you can redistribute it and/or modify
  * it under the terms of the GNU General Public License as published by
  * the Free Software Foundation; either version 2 of the License, or
  * (at your option) any later version.
  *
  * This program is distributed in the hope that it will be useful,
  * but WITHOUT ANY WARRANTY; without even the implied warranty of
  * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  * GNU General Public License for more details.
  *
  * You should have received a copy of the GNU General Public License
  * along with this program; if not, write to the Free Software
  * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
  */

#define _BSD_SOURCE

#include "config.h"

#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
#include <grp.h>
#ifdef HAVE_SHADOW_H
#include <shadow.h>
#endif

#include <glib.h>
#include <glib/gi18n.h>
#include <glib-object.h>
#include <glib/gstdio.h>
#include <gio/gio.h>
#include <gio/gunixinputstream.h>
#include <polkit/polkit.h>

#include "user-classify.h"
#include "daemon.h"
#include "user.h"
#include "accounts-user-generated.h"
#include "util.h"

enum {
        PROP_0,
        PROP_UID,
        PROP_USER_NAME,
        PROP_REAL_NAME,
        PROP_ACCOUNT_TYPE,
        PROP_HOME_DIR,
        PROP_SHELL,
        PROP_EMAIL,
        PROP_LANGUAGE,
        PROP_X_SESSION,
        PROP_LOCATION,
        PROP_LOGIN_FREQUENCY,
        PROP_LOGIN_TIME,
        PROP_LOGIN_HISTORY,
        PROP_ICON_FILE,
        PROP_LOCKED,
        PROP_PASSWORD_MODE,
        PROP_PASSWORD_HINT,
        PROP_AUTOMATIC_LOGIN,
        PROP_SYSTEM_ACCOUNT,
        PROP_LOCAL_ACCOUNT,
};

struct User {
        AccountsUserSkeleton parent;

        GDBusConnection *system_bus_connection;
        gchar *object_path;

        Daemon       *daemon;

        GKeyFile     *keyfile;

        uid_t         uid;
        gid_t         gid;
        gchar        *user_name;
        gchar        *real_name;
        AccountType   account_type;
        PasswordMode  password_mode;
        gchar        *password_hint;
        gchar        *home_dir;
        gchar        *shell;
        gchar        *email;
        gchar        *language;
        gchar        *x_session;
        gchar        *location;
        guint64       login_frequency;
        gint64        login_time;
        gint64        expiration_time;
        gint64        last_change_time;
        gint64        min_days_between_changes;
        gint64        max_days_between_changes;
        gint64        days_to_warn;
        gint64        days_after_expiration_until_lock;
        GVariant     *login_history;
        gchar        *icon_file;
        gchar        *default_icon_file;
        gboolean      locked;
        gboolean      automatic_login;
        gboolean      system_account;
        gboolean      local_account;

        guint        *extension_ids;
        guint         n_extension_ids;
};

typedef struct UserClass
{
        AccountsUserSkeletonClass parent_class;
} UserClass;

static void user_accounts_user_iface_init (AccountsUserIface *iface);

G_DEFINE_TYPE_WITH_CODE (User, user, ACCOUNTS_TYPE_USER_SKELETON, G_IMPLEMENT_INTERFACE (ACCOUNTS_TYPE_USER, user_accounts_user_iface_init));

static gint
account_type_from_pwent (struct passwd *pwent)
{
        struct group *grp;
        gint i;

        if (pwent->pw_uid == 0) {
                g_debug ("user is root so account type is administrator");
                return ACCOUNT_TYPE_ADMINISTRATOR;
        }

        grp = getgrnam (ADMIN_GROUP);
        if (grp == NULL) {
                g_debug (ADMIN_GROUP " group not found");
                return ACCOUNT_TYPE_STANDARD;
        }

        for (i = 0; grp->gr_mem[i] != NULL; i++) {
                if (g_strcmp0 (grp->gr_mem[i], pwent->pw_name) == 0) {
                        return ACCOUNT_TYPE_ADMINISTRATOR;
                }
        }

        return ACCOUNT_TYPE_STANDARD;
}

void
user_update_from_pwent (User          *user,
                        struct passwd *pwent,
                        struct spwd   *spent)
{
        gchar *real_name;
        gboolean changed;
        const gchar *passwd;
        gboolean locked;
        PasswordMode mode;
        AccountType account_type;

        g_object_freeze_notify (G_OBJECT (user));

        changed = FALSE;

        if (pwent->pw_gecos && pwent->pw_gecos[0] != '\0') {
                gchar *first_comma = NULL;
                gchar *valid_utf8_name = NULL;

                if (g_utf8_validate (pwent->pw_gecos, -1, NULL)) {
                        valid_utf8_name = pwent->pw_gecos;
                        first_comma = g_utf8_strchr (valid_utf8_name, -1, ',');
                }
                else {
                        g_warning ("User %s has invalid UTF-8 in GECOS field. "
                                   "It would be a good thing to check /etc/passwd.",
                                   pwent->pw_name ? pwent->pw_name : "");
                }

                if (first_comma) {
                        real_name = g_strndup (valid_utf8_name,
                                                  (first_comma - valid_utf8_name));
                }
                else if (valid_utf8_name) {
                        real_name = g_strdup (valid_utf8_name);
                }
                else {
                        real_name = NULL;
                }

                if (real_name && real_name[0] == '\0') {
                        g_free (real_name);
                        real_name = NULL;
                }
        }
        else {
                real_name = NULL;
        }
        if (g_strcmp0 (real_name, user->real_name) != 0) {
                g_free (user->real_name);
                user->real_name = real_name;
                changed = TRUE;
                g_object_notify (G_OBJECT (user), "real-name");
        }
        else {
                g_free (real_name);
        }

        /* UID */
        if (pwent->pw_uid != user->uid) {
                user->uid = pwent->pw_uid;
                changed = TRUE;
                g_object_notify (G_OBJECT (user), "uid");
        }

        /* GID */
        user->gid = pwent->pw_gid;

        account_type = account_type_from_pwent (pwent);
        if (account_type != user->account_type) {
                user->account_type = account_type;
                changed = TRUE;
                g_object_notify (G_OBJECT (user), "account-type");
        }

        /* Username */
        if (g_strcmp0 (user->user_name, pwent->pw_name) != 0) {
                g_free (user->user_name);
                user->user_name = g_strdup (pwent->pw_name);
                changed = TRUE;
                g_object_notify (G_OBJECT (user), "user-name");
        }

        /* Home Directory */
        if (g_strcmp0 (user->home_dir, pwent->pw_dir) != 0) {
                g_free (user->home_dir);
                user->home_dir = g_strdup (pwent->pw_dir);
                g_free (user->default_icon_file);
                user->default_icon_file = g_build_filename (user->home_dir, ".face", NULL);
                changed = TRUE;
                g_object_notify (G_OBJECT (user), "home-directory");
        }

        /* Shell */
        if (g_strcmp0 (user->shell, pwent->pw_shell) != 0) {
                g_free (user->shell);
                user->shell = g_strdup (pwent->pw_shell);
                changed = TRUE;
                g_object_notify (G_OBJECT (user), "shell");
        }

        passwd = NULL;
        if (spent)
                passwd = spent->sp_pwdp;

        if (passwd && passwd[0] == '!') {
                locked = TRUE;
        }
        else {
                locked = FALSE;
        }

        if (user->locked != locked) {
                user->locked = locked;
                changed = TRUE;
                g_object_notify (G_OBJECT (user), "locked");
        }

        if (passwd == NULL || passwd[0] != 0) {
                mode = PASSWORD_MODE_REGULAR;
        }
        else {
                mode = PASSWORD_MODE_NONE;
        }

        if (spent) {
                if (spent->sp_lstchg == 0) {
                        mode = PASSWORD_MODE_SET_AT_LOGIN;
                }

                user->expiration_time = spent->sp_expire;
                user->last_change_time  = spent->sp_lstchg;
                user->min_days_between_changes = spent->sp_min;
                user->max_days_between_changes = spent->sp_max;
                user->days_to_warn  = spent->sp_warn;
                user->days_after_expiration_until_lock = spent->sp_inact;
        }

        if (user->password_mode != mode) {
                user->password_mode = mode;
                changed = TRUE;
                g_object_notify (G_OBJECT (user), "password-mode");
        }

        user->system_account = !user_classify_is_human (user->uid, user->user_name, pwent->pw_shell, passwd);

        g_object_thaw_notify (G_OBJECT (user));

        if (changed)
                accounts_user_emit_changed (ACCOUNTS_USER (user));
}

void
user_update_from_keyfile (User     *user,
                          GKeyFile *keyfile)
{
        gchar *s;

        g_object_freeze_notify (G_OBJECT (user));

        s = g_key_file_get_string (keyfile, "User", "Language", NULL);
        if (s != NULL) {
                /* TODO: validate / normalize */
                g_free (user->language);
                user->language = s;
                g_object_notify (G_OBJECT (user), "language");
        }

        s = g_key_file_get_string (keyfile, "User", "XSession", NULL);
        if (s != NULL) {
                g_free (user->x_session);
                user->x_session = s;
                g_object_notify (G_OBJECT (user), "xsession");
        }

        s = g_key_file_get_string (keyfile, "User", "Email", NULL);
        if (s != NULL) {
                g_free (user->email);
                user->email = s;
                g_object_notify (G_OBJECT (user), "email");
        }

        s = g_key_file_get_string (keyfile, "User", "Location", NULL);
        if (s != NULL) {
                g_free (user->location);
                user->location = s;
                g_object_notify (G_OBJECT (user), "location");
        }

        s = g_key_file_get_string (keyfile, "User", "PasswordHint", NULL);
        if (s != NULL) {
                g_free (user->password_hint);
                user->password_hint = s;
                g_object_notify (G_OBJECT (user), "password-hint");
        }

        s = g_key_file_get_string (keyfile, "User", "Icon", NULL);
        if (s != NULL) {
                g_free (user->icon_file);
                user->icon_file = s;
                g_object_notify (G_OBJECT (user), "icon-file");
        }

        if (g_key_file_has_key (keyfile, "User", "SystemAccount", NULL)) {
            gboolean system_account;

            system_account = g_key_file_get_boolean (keyfile, "User", "SystemAccount", NULL);
            if (system_account != user->system_account) {
                    user->system_account = system_account;
                    g_object_notify (G_OBJECT (user), "system-account");
            }
        }

        g_clear_pointer (&user->keyfile, g_key_file_unref);
        user->keyfile = g_key_file_ref (keyfile);

        g_object_thaw_notify (G_OBJECT (user));
}

void
user_update_local_account_property (User          *user,
                                    gboolean       local)
{
        if (local == user->local_account)
                return;
        user->local_account = local;
        g_object_notify (G_OBJECT (user), "local-account");
}

void
user_update_system_account_property (User          *user,
                                     gboolean       system)
{
        if (system == user->system_account)
                return;
        user->system_account = system;
        g_object_notify (G_OBJECT (user), "system-account");
}

static void
user_save_to_keyfile (User     *user,
                      GKeyFile *keyfile)
{
        g_key_file_remove_group (keyfile, "User", NULL);

        if (user->email)
                g_key_file_set_string (keyfile, "User", "Email", user->email);

        if (user->language)
                g_key_file_set_string (keyfile, "User", "Language", user->language);

        if (user->x_session)
                g_key_file_set_string (keyfile, "User", "XSession", user->x_session);

        if (user->location)
                g_key_file_set_string (keyfile, "User", "Location", user->location);

        if (user->password_hint)
                g_key_file_set_string (keyfile, "User", "PasswordHint", user->password_hint);

        if (user->icon_file)
                g_key_file_set_string (keyfile, "User", "Icon", user->icon_file);

        g_key_file_set_boolean (keyfile, "User", "SystemAccount", user->system_account);
}

static void
save_extra_data (User *user)
{
        gchar *filename;
        gchar *data;
        GError *error;

        user_save_to_keyfile (user, user->keyfile);

        error = NULL;
        data = g_key_file_to_data (user->keyfile, NULL, &error);
        if (error == NULL) {
                filename = g_build_filename (USERDIR,
                                             user->user_name,
                                             NULL);
                g_file_set_contents (filename, data, -1, &error);
                g_free (filename);
                g_free (data);
        }
        if (error) {
                g_warning ("Saving data for user %s failed: %s",
                           user->user_name, error->message);
                g_error_free (error);
        }
}

static void
move_extra_data (const gchar *old_name,
                 const gchar *new_name)
{
        gchar *old_filename;
        gchar *new_filename;

        old_filename = g_build_filename (USERDIR,
                                         old_name, NULL);
        new_filename = g_build_filename (USERDIR,
                                         new_name, NULL);

        g_rename (old_filename, new_filename);

        g_free (old_filename);
        g_free (new_filename);
}

static GVariant *
user_extension_get_value (User                    *user,
                          GDBusInterfaceInfo      *interface,
                          const GDBusPropertyInfo *property)
{
        const GVariantType *type = G_VARIANT_TYPE (property->signature);
        GVariant *value;
        gchar *printed;
        gint i;

        /* First, try to get the value from the keyfile */
        printed = g_key_file_get_value (user->keyfile, interface->name, property->name, NULL);
        if (printed) {
                value = g_variant_parse (type, printed, NULL, NULL, NULL);
                g_free (printed);

                if (value != NULL)
                        return value;
        }

        /* If that didn't work, try for a default value annotation */
        for (i = 0; property->annotations && property->annotations[i]; i++) {
                GDBusAnnotationInfo *annotation = property->annotations[i];

                if (g_str_equal (annotation->key, "org.freedesktop.Accounts.DefaultValue.String")) {
                        if (g_str_equal (property->signature, "s"))
                                return g_variant_ref_sink (g_variant_new_string (annotation->value));
                }
                else if (g_str_equal (annotation->key, "org.freedesktop.Accounts.DefaultValue")) {
                        value = g_variant_parse (type, annotation->value, NULL, NULL, NULL);
                        if (value != NULL)
                                return value;
                }
        }

        /* Nothing found... */
        return NULL;
}

static void
user_extension_get_property (User                  *user,
                             Daemon                *daemon,
                             GDBusInterfaceInfo    *interface,
                             GDBusMethodInvocation *invocation)
{
        const GDBusPropertyInfo *property = g_dbus_method_invocation_get_property_info (invocation);
        GVariant *value;

        value = user_extension_get_value (user, interface, property);

        if (value) {
                g_dbus_method_invocation_return_value (invocation, g_variant_new ("(v)", value));
                g_variant_unref (value);
        }
        else {
                g_dbus_method_invocation_return_error (invocation, G_DBUS_ERROR, G_DBUS_ERROR_INVALID_ARGS,
                                                       "Key '%s' is not set and has no default value",
                                                       property->name);
        }
}

static void
user_extension_get_all_properties (User                  *user,
                                   Daemon                *daemon,
                                   GDBusInterfaceInfo    *interface,
                                   GDBusMethodInvocation *invocation)
{
        GVariantBuilder builder;
        gint i;

        g_variant_builder_init (&builder, G_VARIANT_TYPE_VARDICT);
        for (i = 0; interface->properties && interface->properties[i]; i++) {
                GDBusPropertyInfo *property = interface->properties[i];
                GVariant *value;

                value = user_extension_get_value (user, interface, property);

                if (value) {
                        g_variant_builder_add (&builder, "{sv}", property->name, value);
                        g_variant_unref (value);
                }
        }

        g_dbus_method_invocation_return_value (invocation, g_variant_new ("(a{sv})", &builder));
}

static void
user_extension_set_property (User                  *user,
                             Daemon                *daemon,
                             GDBusInterfaceInfo    *interface,
                             GDBusMethodInvocation *invocation)
{
        const GDBusPropertyInfo *property = g_dbus_method_invocation_get_property_info (invocation);
        GVariant *value;
        gchar *printed;
        gchar *prev;

        g_variant_get_child (g_dbus_method_invocation_get_parameters (invocation), 2, "v", &value);

        /* We'll always have the type when we parse it back so
         * we don't need it to be printed with annotations.
         */
        printed = g_variant_print (value, FALSE);

        /* May as well try to avoid the thrashing... */
        prev = g_key_file_get_value (user->keyfile, interface->name, property->name, NULL);

        if (!prev || !g_str_equal (printed, prev)) {
                g_key_file_set_value (user->keyfile, interface->name, property->name, printed);

                /* Emit a change signal.  Use invalidation
                 * because the data may not be world-readable.
                 */
                g_dbus_connection_emit_signal (g_dbus_method_invocation_get_connection (invocation),
                                               NULL, /* destination_bus_name */
                                               g_dbus_method_invocation_get_object_path (invocation),
                                               "org.freedesktop.DBus.Properties", "PropertiesChanged",
                                               g_variant_new_parsed ("( %s, %a{sv}, [ %s ] )",
                                                                     interface->name, NULL, property->name),
                                               NULL);

                accounts_user_emit_changed (ACCOUNTS_USER (user));
                save_extra_data (user);
        }

        g_variant_unref (value);
        g_free (printed);
        g_free (prev);

        g_dbus_method_invocation_return_value (invocation, g_variant_new ("()"));
}

static void
user_extension_authentication_done (Daemon                *daemon,
                                    User                  *user,
                                    GDBusMethodInvocation *invocation,
                                    gpointer               user_data)
{
        GDBusInterfaceInfo *interface = user_data;
        const gchar *method_name;

        method_name = g_dbus_method_invocation_get_method_name (invocation);

        if (g_str_equal (method_name, "Get"))
                user_extension_get_property (user, daemon, interface, invocation);
        else if (g_str_equal (method_name, "GetAll"))
                user_extension_get_all_properties (user, daemon, interface, invocation);
        else if (g_str_equal (method_name, "Set"))
                user_extension_set_property (user, daemon, interface, invocation);
        else
                g_assert_not_reached ();
}

static void
user_extension_method_call (GDBusConnection       *connection,
                            const gchar           *sender,
                            const gchar           *object_path,
                            const gchar           *interface_name,
                            const gchar           *method_name,
                            GVariant              *parameters,
                            GDBusMethodInvocation *invocation,
                            gpointer               user_data)
{
        User *user = user_data;
        GDBusInterfaceInfo *iface_info;
        const gchar *annotation_name;
        const gchar *action_id;
        gint uid;
        gint i;

        /* We don't allow method calls on extension interfaces, so we
         * should only ever see property calls here.
         */
        g_assert_cmpstr (interface_name, ==, "org.freedesktop.DBus.Properties");

        /* Now get the real interface name */
        g_variant_get_child (parameters, 0, "&s", &interface_name);

        if (get_caller_uid (invocation, &uid) && (uid_t) uid == user->uid) {
                /* Operation on sender's own User object */
                if (g_str_equal (method_name, "Set")) {
                        annotation_name = "org.freedesktop.Accounts.Authentication.ChangeOwn";
                        action_id = "org.freedesktop.accounts.change-own-user-data";
                }
                else {
                        annotation_name = "org.freedesktop.Accounts.Authentication.ReadOwn";
                        action_id = ""; /* reading allowed by default */
                }
        }
        else {
                /* Operation on someone else's User object */
                if (g_str_equal (method_name, "Set")) {
                        annotation_name = "org.freedesktop.Accounts.Authentication.ChangeAny";
                        action_id = "org.freedesktop.accounts.user-administration";
                }
                else {
                        annotation_name = "org.freedesktop.Accounts.Authentication.ReadAny";
                        action_id = ""; /* reading allowed by default */
                }
        }

        iface_info = g_hash_table_lookup (daemon_get_extension_ifaces (user->daemon), interface_name);
        g_assert (iface_info != NULL);

        for (i = 0; iface_info->annotations && iface_info->annotations[i]; i++) {
                if (g_str_equal (iface_info->annotations[i]->key, annotation_name)) {
                        action_id = iface_info->annotations[i]->value;
                        break;
                }
        }

        if (action_id[0] == '\0') {
                /* Should always allow this call, so just do it now */
                user_extension_authentication_done (user->daemon, user, invocation, iface_info);
        }
        else {
                daemon_local_check_auth (user->daemon, user, action_id, TRUE,
                                         user_extension_authentication_done,
                                         invocation, iface_info, NULL);
        }
}

static void
user_register_extensions (User *user)
{
        static const GDBusInterfaceVTable vtable = {
                user_extension_method_call,
                NULL /* get_property */,
                NULL /* set_property */
        };
        GHashTable *extensions;
        GHashTableIter iter;
        gpointer iface;
        gint i = 0;

        g_assert (user->extension_ids == NULL);
        g_assert (user->n_extension_ids == 0);

        extensions = daemon_get_extension_ifaces (user->daemon);
        user->n_extension_ids = g_hash_table_size (extensions);
        user->extension_ids = g_new (guint, user->n_extension_ids);
        g_hash_table_iter_init (&iter, extensions);

        /* Ignore errors when registering more interfaces because (a)
         * they won't happen and (b) even if they do, we still want to
         * publish the main user interface.
         */
        while (g_hash_table_iter_next (&iter, NULL, &iface))
                user->extension_ids[i++] = g_dbus_connection_register_object (user->system_bus_connection,
                                                                              user->object_path, iface,
                                                                              &vtable, user, NULL, NULL);
}

static gchar *
compute_object_path (User *user)
{
        gchar *object_path;

        object_path = g_strdup_printf ("/org/freedesktop/Accounts/User%lu",
                                       (gulong) user->uid);

        return object_path;
}

void
user_register (User *user)
{
        GError *error = NULL;

        user->system_bus_connection = g_bus_get_sync (G_BUS_TYPE_SYSTEM, NULL, &error);
        if (user->system_bus_connection == NULL) {
                if (error != NULL) {
                        g_critical ("error getting system bus: %s", error->message);
                        g_error_free (error);
                }
                return;
        }

        user->object_path = compute_object_path (user);

        if (!g_dbus_interface_skeleton_export (G_DBUS_INTERFACE_SKELETON (user),
                                               user->system_bus_connection,
                                               user->object_path,
                                               &error)) {
                if (error != NULL) {
                        g_critical ("error exporting user object: %s", error->message);
                        g_error_free (error);
                }
                return;
        }

        user_register_extensions (user);
}

void
user_save (User *user)
{
    save_extra_data (user);
}

void
user_unregister (User *user)
{
        g_dbus_interface_skeleton_unexport (G_DBUS_INTERFACE_SKELETON (user));

        if (user->extension_ids) {
                guint i;

                for (i = 0; i < user->n_extension_ids; i++) {
                        /* In theory, if an error happened during registration, we could have 0 here. */
                        if (user->extension_ids[i] == 0)
                                continue;

                        g_dbus_connection_unregister_object (user->system_bus_connection, user->extension_ids[i]);
                }

                g_clear_pointer (&user->extension_ids, g_free);
                user->n_extension_ids = 0;
        }
}

void
user_changed (User *user)
{
        accounts_user_emit_changed (ACCOUNTS_USER (user));
}

User *
user_new (Daemon *daemon,
          uid_t   uid)
{
        User *user;

        user = g_object_new (TYPE_USER, NULL);
        user->daemon = daemon;
        user->uid = uid;

        return user;
}

const gchar *
user_get_user_name (User *user)
{
        return user->user_name;
}

gboolean
user_get_system_account (User *user)
{
        return user->system_account;
}

gboolean
user_get_local_account (User *user)
{
        return user->local_account;
}

const gchar *
user_get_object_path (User *user)
{
        return user->object_path;
}

uid_t
user_get_uid (User *user)
{
        return user->uid;
}

const gchar *
user_get_shell(User *user)
{
	return user->shell;
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

static void
user_change_real_name_authorized_cb (Daemon                *daemon,
                                     User                  *user,
                                     GDBusMethodInvocation *context,
                                     gpointer               data)

{
        gchar *name = data;
        GError *error;
        const gchar *argv[6];

        if (g_strcmp0 (user->real_name, name) != 0) {
                sys_log (context,
                         "change real name of user '%s' (%d) to '%s'",
                         user->user_name, user->uid, name);

                argv[0] = "/usr/sbin/usermod";
                argv[1] = "-c";
                argv[2] = name;
                argv[3] = "--";
                argv[4] = user->user_name;
                argv[5] = NULL;

                error = NULL;
                if (!spawn_with_login_uid (context, argv, &error)) {
                        throw_error (context, ERROR_FAILED, "running '%s' failed: %s", argv[0], error->message);
                        g_error_free (error);
                        return;
                }

                g_free (user->real_name);
                user->real_name = g_strdup (name);

                accounts_user_emit_changed (ACCOUNTS_USER (user));

                g_object_notify (G_OBJECT (user), "real-name");
        }

        accounts_user_complete_set_real_name (ACCOUNTS_USER (user), context);
}

static gboolean
user_set_real_name (AccountsUser          *auser,
                    GDBusMethodInvocation *context,
                    const gchar           *real_name)
{
        User *user = (User*)auser;
        int uid;
        const gchar *action_id;

        if (!get_caller_uid (context, &uid)) {
                throw_error (context, ERROR_FAILED, "identifying caller failed");
                return FALSE;
        }

        if (user->uid == (uid_t) uid)
                action_id = "org.freedesktop.accounts.change-own-user-data";
        else
                action_id = "org.freedesktop.accounts.user-administration";

        daemon_local_check_auth (user->daemon,
                                 user,
                                 action_id,
                                 TRUE,
                                 user_change_real_name_authorized_cb,
                                 context,
                                 g_strdup (real_name),
                                 (GDestroyNotify)g_free);

        return TRUE;
}

static void
user_change_user_name_authorized_cb (Daemon                *daemon,
                                     User                  *user,
                                     GDBusMethodInvocation *context,
                                     gpointer               data)

{
        gchar *name = data;
        gchar *old_name;
        GError *error;
        const gchar *argv[6];

        if (g_strcmp0 (user->user_name, name) != 0) {
                old_name = g_strdup (user->user_name);
                sys_log (context,
                         "change name of user '%s' (%d) to '%s'",
                         old_name, user->uid, name);

                argv[0] = "/usr/sbin/usermod";
                argv[1] = "-l";
                argv[2] = name;
                argv[3] = "--";
                argv[4] = user->user_name;
                argv[5] = NULL;

                error = NULL;
                if (!spawn_with_login_uid (context, argv, &error)) {
                        throw_error (context, ERROR_FAILED, "running '%s' failed: %s", argv[0], error->message);
                        g_error_free (error);
                        return;
                }

                g_free (user->user_name);
                user->user_name = g_strdup (name);

                move_extra_data (old_name, name);

                accounts_user_emit_changed (ACCOUNTS_USER (user));

                g_object_notify (G_OBJECT (user), "user-name");
        }

        accounts_user_complete_set_user_name (ACCOUNTS_USER (user), context);
}


static gboolean
user_set_user_name (AccountsUser          *auser,
                    GDBusMethodInvocation *context,
                    const gchar           *user_name)
{
        User *user = (User*)auser;
        daemon_local_check_auth (user->daemon,
                                 user,
                                 "org.freedesktop.accounts.user-administration",
                                 TRUE,
                                 user_change_user_name_authorized_cb,
                                 context,
                                 g_strdup (user_name),
                                 (GDestroyNotify)g_free);

        return TRUE;
}

static void
user_change_email_authorized_cb (Daemon                *daemon,
                                 User                  *user,
                                 GDBusMethodInvocation *context,
                                 gpointer               data)

{
        gchar *email = data;

        if (g_strcmp0 (user->email, email) != 0) {
                g_free (user->email);
                user->email = g_strdup (email);

                save_extra_data (user);

                accounts_user_emit_changed (ACCOUNTS_USER (user));

                g_object_notify (G_OBJECT (user), "email");
        }

        accounts_user_complete_set_email (ACCOUNTS_USER (user), context);
}



static gboolean
user_set_email (AccountsUser          *auser,
                GDBusMethodInvocation *context,
                const gchar           *email)
{
        User *user = (User*)auser;
        int uid;
        const gchar *action_id;

        if (!get_caller_uid (context, &uid)) {
                throw_error (context, ERROR_FAILED, "identifying caller failed");
                return FALSE;
        }

        if (user->uid == (uid_t) uid)
                action_id = "org.freedesktop.accounts.change-own-user-data";
        else
                action_id = "org.freedesktop.accounts.user-administration";

        daemon_local_check_auth (user->daemon,
                                 user,
                                 action_id,
                                 TRUE,
                                 user_change_email_authorized_cb,
                                 context,
                                 g_strdup (email),
                                 (GDestroyNotify)g_free);

        return TRUE;
}

static void
user_change_language_authorized_cb (Daemon                *daemon,
                                    User                  *user,
                                    GDBusMethodInvocation *context,
                                    gpointer               data)

{
        gchar *language = data;

        if (g_strcmp0 (user->language, language) != 0) {
                g_free (user->language);
                user->language = g_strdup (language);

                save_extra_data (user);

                accounts_user_emit_changed (ACCOUNTS_USER (user));

                g_object_notify (G_OBJECT (user), "language");
        }

        accounts_user_complete_set_language (ACCOUNTS_USER (user), context);
}



static gboolean
user_set_language (AccountsUser          *auser,
                   GDBusMethodInvocation *context,
                   const gchar           *language)
{
        User *user = (User*)auser;
        int uid;
        const gchar *action_id;

        if (!get_caller_uid (context, &uid)) {
                throw_error (context, ERROR_FAILED, "identifying caller failed");
                return FALSE;
        }

        if (user->uid == (uid_t) uid)
                action_id = "org.freedesktop.accounts.change-own-user-data";
        else
                action_id = "org.freedesktop.accounts.user-administration";

        daemon_local_check_auth (user->daemon,
                                 user,
                                 action_id,
                                 TRUE,
                                 user_change_language_authorized_cb,
                                 context,
                                 g_strdup (language),
                                 (GDestroyNotify)g_free);

        return TRUE;
}

static void
user_change_x_session_authorized_cb (Daemon                *daemon,
                                     User                  *user,
                                     GDBusMethodInvocation *context,
                                     gpointer               data)

{
        gchar *x_session = data;

        if (g_strcmp0 (user->x_session, x_session) != 0) {
                g_free (user->x_session);
                user->x_session = g_strdup (x_session);

                save_extra_data (user);

                accounts_user_emit_changed (ACCOUNTS_USER (user));

                g_object_notify (G_OBJECT (user), "xsession");
        }

        accounts_user_complete_set_xsession (ACCOUNTS_USER (user), context);
}

static gboolean
user_set_x_session (AccountsUser          *auser,
                    GDBusMethodInvocation *context,
                    const gchar           *x_session)
{
        User *user = (User*)auser;
        int uid;
        const gchar *action_id;

        if (!get_caller_uid (context, &uid)) {
                throw_error (context, ERROR_FAILED, "identifying caller failed");
                return FALSE;
        }

        if (user->uid == (uid_t) uid)
                action_id = "org.freedesktop.accounts.change-own-user-data";
        else
                action_id = "org.freedesktop.accounts.user-administration";

        daemon_local_check_auth (user->daemon,
                                 user,
                                 action_id,
                                 TRUE,
                                 user_change_x_session_authorized_cb,
                                 context,
                                 g_strdup (x_session),
                                 (GDestroyNotify) g_free);

        return TRUE;
}

static void
user_get_password_expiration_policy_authorized_cb (Daemon                *daemon,
                                                   User                  *user,
                                                   GDBusMethodInvocation *context,
                                                   gpointer               data)

{
        accounts_user_complete_get_password_expiration_policy (ACCOUNTS_USER (user),
                                                               context,
                                                               user->expiration_time,
                                                               user->last_change_time,
                                                               user->min_days_between_changes,
                                                               user->max_days_between_changes,
                                                               user->days_to_warn,
                                                               user->days_after_expiration_until_lock);
}

static gboolean
user_get_password_expiration_policy (AccountsUser          *auser,
                                     GDBusMethodInvocation *context)
{
        User *user = (User*)auser;
        int uid;
        const gchar *action_id;

        if (!get_caller_uid (context, &uid)) {
                throw_error (context, ERROR_FAILED, "identifying caller failed");
                return FALSE;
        }

        if (user->uid == (uid_t) uid)
                action_id = "org.freedesktop.accounts.change-own-user-data";
        else
                action_id = "org.freedesktop.accounts.user-administration";

        daemon_local_check_auth (user->daemon,
                                 user,
                                 action_id,
                                 TRUE,
                                 user_get_password_expiration_policy_authorized_cb,
                                 context,
                                 NULL,
                                 NULL);

        return TRUE;
}


static void
user_change_location_authorized_cb (Daemon                *daemon,
                                    User                  *user,
                                    GDBusMethodInvocation *context,
                                    gpointer               data)

{
        gchar *location = data;

        if (g_strcmp0 (user->location, location) != 0) {
                g_free (user->location);
                user->location = g_strdup (location);

                save_extra_data (user);

                accounts_user_emit_changed (ACCOUNTS_USER (user));

                g_object_notify (G_OBJECT (user), "location");
        }

        accounts_user_complete_set_location (ACCOUNTS_USER (user), context);
}

static gboolean
user_set_location (AccountsUser          *auser,
                   GDBusMethodInvocation *context,
                   const gchar           *location)
{
        User *user = (User*)auser;
        int uid;
        const gchar *action_id;

        if (!get_caller_uid (context, &uid)) {
                throw_error (context, ERROR_FAILED, "identifying caller failed");
                return FALSE;
        }

        if (user->uid == (uid_t) uid)
                action_id = "org.freedesktop.accounts.change-own-user-data";
        else
                action_id = "org.freedesktop.accounts.user-administration";

        daemon_local_check_auth (user->daemon,
                                 user,
                                 action_id,
                                 TRUE,
                                 user_change_location_authorized_cb,
                                 context,
                                 g_strdup (location),
                                 (GDestroyNotify)g_free);

        return TRUE;
}

static void
user_change_home_dir_authorized_cb (Daemon                *daemon,
                                    User                  *user,
                                    GDBusMethodInvocation *context,
                                    gpointer               data)

{
        gchar *home_dir = data;
        GError *error;
        const gchar *argv[7];

        if (g_strcmp0 (user->home_dir, home_dir) != 0) {
                sys_log (context,
                         "change home directory of user '%s' (%d) to '%s'",
                         user->user_name, user->uid, home_dir);

                argv[0] = "/usr/sbin/usermod";
                argv[1] = "-m";
                argv[2] = "-d";
                argv[3] = home_dir;
                argv[4] = "--";
                argv[5] = user->user_name;
                argv[6] = NULL;

                error = NULL;
                if (!spawn_with_login_uid (context, argv, &error)) {
                        throw_error (context, ERROR_FAILED, "running '%s' failed: %s", argv[0], error->message);
                        g_error_free (error);
                        return;
                }

                g_free (user->home_dir);
                user->home_dir = g_strdup (home_dir);
                g_free (user->default_icon_file);
                user->default_icon_file = g_build_filename (user->home_dir, ".face", NULL);

                accounts_user_emit_changed (ACCOUNTS_USER (user));

                g_object_notify (G_OBJECT (user), "home-directory");
        }

        accounts_user_complete_set_home_directory (ACCOUNTS_USER (user), context);
}

static gboolean
user_set_home_directory (AccountsUser          *auser,
                         GDBusMethodInvocation *context,
                         const gchar           *home_dir)
{
        User *user = (User*)auser;
        daemon_local_check_auth (user->daemon,
                                 user,
                                 "org.freedesktop.accounts.user-administration",
                                 TRUE,
                                 user_change_home_dir_authorized_cb,
                                 context,
                                 g_strdup (home_dir),
                                 (GDestroyNotify)g_free);

        return TRUE;
}

static void
user_change_shell_authorized_cb (Daemon                *daemon,
                                 User                  *user,
                                 GDBusMethodInvocation *context,
                                 gpointer               data)

{
        gchar *shell = data;
        GError *error;
        const gchar *argv[6];

        if (g_strcmp0 (user->shell, shell) != 0) {
                sys_log (context,
                         "change shell of user '%s' (%d) to '%s'",
                         user->user_name, user->uid, shell);

                argv[0] = "/usr/sbin/usermod";
                argv[1] = "-s";
                argv[2] = shell;
                argv[3] = "--";
                argv[4] = user->user_name;
                argv[5] = NULL;

                error = NULL;
                if (!spawn_with_login_uid (context, argv, &error)) {
                        throw_error (context, ERROR_FAILED, "running '%s' failed: %s", argv[0], error->message);
                        g_error_free (error);
                        return;
                }

                g_free (user->shell);
                user->shell = g_strdup (shell);

                accounts_user_emit_changed (ACCOUNTS_USER (user));

                g_object_notify (G_OBJECT (user), "shell");
        }

        accounts_user_complete_set_shell (ACCOUNTS_USER (user), context);
}

static gboolean
user_set_shell (AccountsUser          *auser,
                GDBusMethodInvocation *context,
                const gchar           *shell)
{
        User *user = (User*)auser;
        daemon_local_check_auth (user->daemon,
                                 user,
                                 "org.freedesktop.accounts.user-administration",
                                 TRUE,
                                 user_change_shell_authorized_cb,
                                 context,
                                 g_strdup (shell),
                                 (GDestroyNotify)g_free);

        return TRUE;
}

static void
become_user (gpointer data)
{
        struct passwd *pw = data;

        if (pw == NULL ||
            initgroups (pw->pw_name, pw->pw_gid) != 0 ||
            setgid (pw->pw_gid) != 0 ||
            setuid (pw->pw_uid) != 0) {
                exit (1);
        }
}

static void
user_change_icon_file_authorized_cb (Daemon                *daemon,
                                     User                  *user,
                                     GDBusMethodInvocation *context,
                                     gpointer               data)

{
        gchar *filename;
        GFile *file;
        GFileInfo *info;
        guint32 mode;
        GFileType type;
        guint64 size;

        filename = g_strdup (data);

        if (filename == NULL ||
            *filename == '\0') {
                char *dest_path;
                GFile *dest;
                GError *error;

                g_free (filename);
                filename = NULL;

                dest_path = g_build_filename (ICONDIR, user->user_name, NULL);
                dest = g_file_new_for_path (dest_path);
                g_free (dest_path);

                error = NULL;
                if (!g_file_delete (dest, NULL, &error) &&
                    !g_error_matches (error, G_IO_ERROR, G_IO_ERROR_NOT_FOUND)) {
                        g_object_unref (dest);
                        throw_error (context, ERROR_FAILED, "failed to remove user icon, %s", error->message);
                        g_error_free (error);
                        return;
                }
                g_object_unref (dest);
                goto icon_saved;
        }

        file = g_file_new_for_path (filename);
        info = g_file_query_info (file, G_FILE_ATTRIBUTE_UNIX_MODE ","
                                        G_FILE_ATTRIBUTE_STANDARD_TYPE ","
                                        G_FILE_ATTRIBUTE_STANDARD_SIZE,
                                  0, NULL, NULL);
        mode = g_file_info_get_attribute_uint32 (info, G_FILE_ATTRIBUTE_UNIX_MODE);
        type = g_file_info_get_file_type (info);
        size = g_file_info_get_attribute_uint64 (info, G_FILE_ATTRIBUTE_STANDARD_SIZE);

        g_object_unref (info);
        g_object_unref (file);

        if (type != G_FILE_TYPE_REGULAR) {
                g_debug ("not a regular file");
                throw_error (context, ERROR_FAILED, "file '%s' is not a regular file", filename);
                g_free (filename);
                return;
        }

        if (size > 1048576) {
                g_debug ("file too large");
                /* 1MB ought to be enough for everybody */
                throw_error (context, ERROR_FAILED, "file '%s' is too large to be used as an icon", filename);
                g_free (filename);
                return;
        }

        if ((mode & S_IROTH) == 0 ||
            (!g_str_has_prefix (filename, DATADIR) &&
             !g_str_has_prefix (filename, ICONDIR))) {
                gchar *dest_path;
                GFile *dest;
                const gchar *argv[3];
                gint std_out;
                GError *error;
                GInputStream *input;
                GOutputStream *output;
                gint uid;
                gssize bytes;
                struct passwd *pw;

                if (!get_caller_uid (context, &uid)) {
                        throw_error (context, ERROR_FAILED, "failed to copy file, could not determine caller UID");
                        g_free (filename);
                        return;
                }

                dest_path = g_build_filename (ICONDIR, user->user_name, NULL);
                dest = g_file_new_for_path (dest_path);

                error = NULL;
                output = G_OUTPUT_STREAM (g_file_replace (dest, NULL, FALSE, 0, NULL, &error));
                if (!output) {
                        throw_error (context, ERROR_FAILED, "creating file '%s' failed: %s", dest_path, error->message);
                        g_error_free (error);
                        g_free (filename);
                        g_free (dest_path);
                        g_object_unref (dest);
                        return;
                }

                argv[0] = "/bin/cat";
                argv[1] = filename;
                argv[2] = NULL;

                pw = getpwuid (uid);

                error = NULL;
                if (!g_spawn_async_with_pipes (NULL, (gchar**)argv, NULL, 0, become_user, pw, NULL, NULL, &std_out, NULL, &error)) {
                        throw_error (context, ERROR_FAILED, "reading file '%s' failed: %s", filename, error->message);
                        g_error_free (error);
                        g_free (filename);
                        g_free (dest_path);
                        g_object_unref (dest);
                        return;
                }

                input = g_unix_input_stream_new (std_out, FALSE);

                error = NULL;
                bytes = g_output_stream_splice (output, input, G_OUTPUT_STREAM_SPLICE_CLOSE_TARGET, NULL, &error);
                if (bytes < 0 || (gsize)bytes != size) {
                        throw_error (context, ERROR_FAILED, "copying file '%s' to '%s' failed: %s", filename, dest_path, error ? error->message : "unknown reason");
                        if (error)
                                g_error_free (error);

                        g_file_delete (dest, NULL, NULL);

                        g_free (filename);
                        g_free (dest_path);
                        g_object_unref (dest);
                        g_object_unref (input);
                        g_object_unref (output);
                        return;
                }

                g_object_unref (dest);
                g_object_unref (input);
                g_object_unref (output);

                g_free (filename);
                filename = dest_path;
        }

icon_saved:
        g_free (user->icon_file);
        user->icon_file = filename;

        save_extra_data (user);

        accounts_user_emit_changed (ACCOUNTS_USER (user));

        g_object_notify (G_OBJECT (user), "icon-file");

        accounts_user_complete_set_icon_file (ACCOUNTS_USER (user), context);
}

static gboolean
user_set_icon_file (AccountsUser          *auser,
                    GDBusMethodInvocation *context,
                    const gchar           *filename)
{
        User *user = (User*)auser;
        int uid;
        const gchar *action_id;

        if (!get_caller_uid (context, &uid)) {
                throw_error (context, ERROR_FAILED, "identifying caller failed");
                return FALSE;
        }

        if (user->uid == (uid_t) uid)
                action_id = "org.freedesktop.accounts.change-own-user-data";
        else
                action_id = "org.freedesktop.accounts.user-administration";

        daemon_local_check_auth (user->daemon,
                                 user,
                                 action_id,
                                 TRUE,
                                 user_change_icon_file_authorized_cb,
                                 context,
                                 g_strdup (filename),
                                 (GDestroyNotify)g_free);

        return TRUE;
}

static void
user_change_locked_authorized_cb (Daemon                *daemon,
                                  User                  *user,
                                  GDBusMethodInvocation *context,
                                  gpointer               data)

{
        gboolean locked = GPOINTER_TO_INT (data);
        GError *error;
        const gchar *argv[5];

        if (user->locked != locked) {
                sys_log (context,
                         "%s account of user '%s' (%d)",
                         locked ? "locking" : "unlocking", user->user_name, user->uid);
                argv[0] = "/usr/sbin/usermod";
                argv[1] = locked ? "-L" : "-U";
                argv[2] = "--";
                argv[3] = user->user_name;
                argv[4] = NULL;

                error = NULL;
                if (!spawn_with_login_uid (context, argv, &error)) {
                        throw_error (context, ERROR_FAILED, "running '%s' failed: %s", argv[0], error->message);
                        g_error_free (error);
                        return;
                }

                user->locked = locked;

                if (user->automatic_login) {
                    User *automatic_login_user;

                    automatic_login_user = daemon_local_get_automatic_login_user (daemon);
                    if (user->locked) {
                            /* If automatic login is enabled for the user then
                             * disable it in the config file, but keep the state
                             * attached to the user unharmed so it can be restored
                             * later in the session
                             */
                            if (user == automatic_login_user) {
                                    daemon_local_set_automatic_login (daemon, user, FALSE, NULL);
                                    user->automatic_login = TRUE;
                            }
                    } else {
                            if (automatic_login_user == NULL) {
                                    user->automatic_login = FALSE;
                                    daemon_local_set_automatic_login (daemon, user, TRUE, NULL);
                            }
                    }
                }

                accounts_user_emit_changed (ACCOUNTS_USER (user));

                g_object_notify (G_OBJECT (user), "locked");
        }

        accounts_user_complete_set_locked (ACCOUNTS_USER (user), context);
}

static gboolean
user_set_locked (AccountsUser          *auser,
                 GDBusMethodInvocation *context,
                 gboolean               locked)
{
        User *user = (User*)auser;
        daemon_local_check_auth (user->daemon,
                                 user,
                                 "org.freedesktop.accounts.user-administration",
                                 TRUE,
                                 user_change_locked_authorized_cb,
                                 context,
                                 GINT_TO_POINTER (locked),
                                 NULL);

        return TRUE;
}

static void
user_change_account_type_authorized_cb (Daemon                *daemon,
                                        User                  *user,
                                        GDBusMethodInvocation *context,
                                        gpointer               data)

{
        AccountType account_type = GPOINTER_TO_INT (data);
        GError *error;
        gid_t *groups;
        gint ngroups;
        GString *str;
        gid_t wheel;
        struct group *grp;
        gint i;
        const gchar *argv[6];

        if (user->account_type != account_type) {
                sys_log (context,
                         "change account type of user '%s' (%d) to %d",
                         user->user_name, user->uid, account_type);

                grp = getgrnam (ADMIN_GROUP);
                if (grp == NULL) {
                        throw_error (context, ERROR_FAILED, "failed to set account type: wheel group not found");
                        return;
                }
                wheel = grp->gr_gid;

                ngroups = get_user_groups (user->user_name, user->gid, &groups);

                str = g_string_new ("");
                for (i = 0; i < ngroups; i++) {
                        if (groups[i] == wheel)
                                continue;
                        g_string_append_printf (str, "%d,", groups[i]);
                }
                switch (account_type) {
                case ACCOUNT_TYPE_ADMINISTRATOR:
                        g_string_append_printf (str, "%d", wheel);
                        break;
                case ACCOUNT_TYPE_STANDARD:
                default:
                        /* remove excess comma */
                        g_string_truncate (str, str->len - 1);
                        break;
                }

                g_free (groups);

                argv[0] = "/usr/sbin/usermod";
                argv[1] = "-G";
                argv[2] = str->str;
                argv[3] = "--";
                argv[4] = user->user_name;
                argv[5] = NULL;

                g_string_free (str, FALSE);

                error = NULL;
                if (!spawn_with_login_uid (context, argv, &error)) {
                        throw_error (context, ERROR_FAILED, "running '%s' failed: %s", argv[0], error->message);
                        g_error_free (error);
                        return;
                }

                user->account_type = account_type;

                accounts_user_emit_changed (ACCOUNTS_USER (user));

                g_object_notify (G_OBJECT (user), "account-type");
        }

        accounts_user_complete_set_account_type (ACCOUNTS_USER (user), context);
}

static gboolean
user_set_account_type (AccountsUser          *auser,
                       GDBusMethodInvocation *context,
                       gint                   account_type)
{
        User *user = (User*)auser;
        if (account_type < 0 || account_type > ACCOUNT_TYPE_LAST) {
                throw_error (context, ERROR_FAILED, "unknown account type: %d", account_type);
                return FALSE;
        }

        daemon_local_check_auth (user->daemon,
                                 user,
                                 "org.freedesktop.accounts.user-administration",
                                 TRUE,
                                 user_change_account_type_authorized_cb,
                                 context,
                                 GINT_TO_POINTER (account_type),
                                 NULL);

        return TRUE;
}

static void
user_change_password_mode_authorized_cb (Daemon                *daemon,
                                         User                  *user,
                                         GDBusMethodInvocation *context,
                                         gpointer               data)

{
        PasswordMode mode = GPOINTER_TO_INT (data);
        GError *error;
        const gchar *argv[6];

        if (user->password_mode != mode) {
                sys_log (context,
                         "change password mode of user '%s' (%d) to %d",
                         user->user_name, user->uid, mode);

                g_object_freeze_notify (G_OBJECT (user));

                if (mode == PASSWORD_MODE_SET_AT_LOGIN ||
                    mode == PASSWORD_MODE_NONE) {

                        argv[0] = "/usr/bin/passwd";
                        argv[1] = "-d";
                        argv[2] = "--";
                        argv[3] = user->user_name;
                        argv[4] = NULL;

                        error = NULL;
                        if (!spawn_with_login_uid (context, argv, &error)) {
                                throw_error (context, ERROR_FAILED, "running '%s' failed: %s", argv[0], error->message);
                                g_error_free (error);
                                return;
                        }

                        if (mode == PASSWORD_MODE_SET_AT_LOGIN) {
                                argv[0] = "/usr/bin/chage";
                                argv[1] = "-d";
                                argv[2] = "0";
                                argv[3] = "--";
                                argv[4] = user->user_name;
                                argv[5] = NULL;

                                error = NULL;
                                if (!spawn_with_login_uid (context, argv, &error)) {
                                        throw_error (context, ERROR_FAILED, "running '%s' failed: %s", argv[0], error->message);
                                        g_error_free (error);
                                        return;
                                }
                        }

                        g_free (user->password_hint);
                        user->password_hint = NULL;

                        g_object_notify (G_OBJECT (user), "password-hint");

                        /* removing the password has the side-effect of
                         * unlocking the account
                         */
                        if (user->locked) {
                                user->locked = FALSE;
                                g_object_notify (G_OBJECT (user), "locked");
                        }
                }
                else if (user->locked) {
                        argv[0] = "/usr/sbin/usermod";
                        argv[1] = "-U";
                        argv[2] = "--";
                        argv[3] = user->user_name;
                        argv[4] = NULL;

                        error = NULL;
                        if (!spawn_with_login_uid (context, argv, &error)) {
                                throw_error (context, ERROR_FAILED, "running '%s' failed: %s", argv[0], error->message);
                                g_error_free (error);
                                return;
                        }

                        user->locked = FALSE;
                        g_object_notify (G_OBJECT (user), "locked");
                }

                user->password_mode = mode;

                g_object_notify (G_OBJECT (user), "password-mode");

                save_extra_data (user);

                g_object_thaw_notify (G_OBJECT (user));

                accounts_user_emit_changed (ACCOUNTS_USER (user));
        }

        accounts_user_complete_set_password_mode (ACCOUNTS_USER (user), context);
}

static gboolean
user_set_password_mode (AccountsUser          *auser,
                        GDBusMethodInvocation *context,
                        gint                   mode)
{
        User *user = (User*)auser;
        const gchar *action_id;

        if (mode < 0 || mode > PASSWORD_MODE_LAST) {
                throw_error (context, ERROR_FAILED, "unknown password mode: %d", mode);
                return FALSE;
        }

        action_id = "org.freedesktop.accounts.user-administration";

        daemon_local_check_auth (user->daemon,
                                 user,
                                 action_id,
                                 TRUE,
                                 user_change_password_mode_authorized_cb,
                                 context,
                                 GINT_TO_POINTER (mode),
                                 NULL);

        return TRUE;
}

static void
user_change_password_authorized_cb (Daemon                *daemon,
                                    User                  *user,
                                    GDBusMethodInvocation *context,
                                    gpointer               data)

{
        gchar **strings = data;
        GError *error;
        const gchar *argv[6];

        sys_log (context,
                 "set password and hint of user '%s' (%d)",
                 user->user_name, user->uid);

        g_object_freeze_notify (G_OBJECT (user));

        argv[0] = "/usr/sbin/usermod";
        argv[1] = "-p";
        argv[2] = strings[0];
        argv[3] = "--";
        argv[4] = user->user_name;
        argv[5] = NULL;

        error = NULL;
        if (!spawn_with_login_uid (context, argv, &error)) {
                throw_error (context, ERROR_FAILED, "running '%s' failed: %s", argv[0], error->message);
                g_error_free (error);
                return;
        }

        if (user->password_mode != PASSWORD_MODE_REGULAR) {
                user->password_mode = PASSWORD_MODE_REGULAR;
                g_object_notify (G_OBJECT (user), "password-mode");
        }

        if (user->locked) {
                user->locked = FALSE;
                g_object_notify (G_OBJECT (user), "locked");
        }

        if (g_strcmp0 (user->password_hint, strings[1]) != 0) {
                g_free (user->password_hint);
                user->password_hint = g_strdup (strings[1]);
                g_object_notify (G_OBJECT (user), "password-hint");
        }

        save_extra_data (user);

        g_object_thaw_notify (G_OBJECT (user));

        accounts_user_emit_changed (ACCOUNTS_USER (user));

        accounts_user_complete_set_password (ACCOUNTS_USER (user), context);
}

static void
free_passwords (gchar **strings)
{
        memset (strings[0], 0, strlen (strings[0]));
        g_strfreev (strings);
}

static gboolean
user_set_password (AccountsUser          *auser,
                   GDBusMethodInvocation *context,
                   const gchar           *password,
                   const gchar           *hint)
{
        User *user = (User*)auser;
        gchar **data;

        data = g_new (gchar *, 3);
        data[0] = g_strdup (password);
        data[1] = g_strdup (hint);
        data[2] = NULL;

        daemon_local_check_auth (user->daemon,
                                 user,
                                 "org.freedesktop.accounts.user-administration",
                                 TRUE,
                                 user_change_password_authorized_cb,
                                 context,
                                 data,
                                 (GDestroyNotify)free_passwords);

        memset ((char*)password, 0, strlen (password));

        return TRUE;
}

static void
user_change_password_hint_authorized_cb (Daemon                *daemon,
                                         User                  *user,
                                         GDBusMethodInvocation *context,
                                         gpointer               data)
{
        gchar *hint = data;

        sys_log (context,
                 "set password hint of user '%s' (%d)'",
                 user->user_name, user->uid);

        if (g_strcmp0 (user->password_hint, hint) != 0) {
                g_free (user->password_hint);
                user->password_hint = g_strdup (hint);

                save_extra_data (user);

                accounts_user_emit_changed (ACCOUNTS_USER (user));

                g_object_notify (G_OBJECT (user), "password-hint");
        }

        accounts_user_complete_set_password_hint (ACCOUNTS_USER (user), context);
}

static gboolean
user_set_password_hint (AccountsUser          *auser,
                        GDBusMethodInvocation *context,
                        const gchar           *hint)
{
        User *user = (User*)auser;
        int uid;
        const gchar *action_id;

        if (!get_caller_uid (context, &uid)) {
                throw_error (context, ERROR_FAILED, "identifying caller failed");
                return FALSE;
        }

        if (user->uid == (uid_t) uid)
                action_id = "org.freedesktop.accounts.change-own-user-data";
        else
                action_id = "org.freedesktop.accounts.user-administration";

        daemon_local_check_auth (user->daemon,
                                 user,
                                 action_id,
                                 TRUE,
                                 user_change_password_hint_authorized_cb,
                                 context,
                                 g_strdup (hint),
                                 (GDestroyNotify)g_free);

        return TRUE;
}

static void
user_change_automatic_login_authorized_cb (Daemon                *daemon,
                                           User                  *user,
                                           GDBusMethodInvocation *context,
                                           gpointer               data)
{
        gboolean enabled = GPOINTER_TO_INT (data);
        GError *error = NULL;

        sys_log (context,
                 "%s automatic login for user '%s' (%d)",
                 enabled ? "enable" : "disable", user->user_name, user->uid);

        if (user->locked) {
                throw_error (context, ERROR_FAILED, "failed to change automatic login: user is locked");
                return;
        }

        if (!daemon_local_set_automatic_login (daemon, user, enabled, &error)) {
                throw_error (context, ERROR_FAILED, "failed to change automatic login: %s", error->message);
                g_error_free (error);
                return;
        }

        accounts_user_complete_set_automatic_login (ACCOUNTS_USER (user), context);
}

static gboolean
user_set_automatic_login (AccountsUser          *auser,
                          GDBusMethodInvocation *context,
                          gboolean               enabled)
{
        User *user = (User*)auser;
        daemon_local_check_auth (user->daemon,
                                 user,
                                 "org.freedesktop.accounts.user-administration",
                                 TRUE,
                                 user_change_automatic_login_authorized_cb,
                                 context,
                                 GINT_TO_POINTER (enabled),
                                 NULL);

        return TRUE;
}

static guint64
user_real_get_uid (AccountsUser *user)
{
        return (guint64) USER (user)->uid;
}

static const gchar *
user_real_get_user_name (AccountsUser *user)
{
        return USER (user)->user_name;
}

static const gchar *
user_real_get_real_name (AccountsUser *user)
{
        return USER (user)->real_name;
}

static gint
user_real_get_account_type (AccountsUser *user)
{
        return (gint) USER (user)->account_type;
}

static const gchar *
user_real_get_home_directory (AccountsUser *user)
{
        return USER (user)->home_dir;
}

static const gchar *
user_real_get_shell (AccountsUser *user)
{
        return USER (user)->shell;
}

static const gchar *
user_real_get_email (AccountsUser *user)
{
        return USER (user)->email;
}

static const gchar *
user_real_get_language (AccountsUser *user)
{
        return USER (user)->language;
}

static const gchar *
user_real_get_xsession (AccountsUser *user)
{
        return USER (user)->x_session;
}

static const gchar *
user_real_get_location (AccountsUser *user)
{
        return USER (user)->location;
}

static guint64
user_real_get_login_frequency (AccountsUser *user)
{
        return USER (user)->login_frequency;
}

static gint64
user_real_get_login_time (AccountsUser *user)
{
        return USER (user)->login_time;
}

static GVariant *
user_real_get_login_history (AccountsUser *user)
{
        return USER (user)->login_history;
}

static const gchar *
user_real_get_icon_file (AccountsUser *user)
{
        if (USER (user)->icon_file)
                return USER (user)->icon_file;
        else
                return USER (user)->default_icon_file;
}

static gboolean
user_real_get_locked (AccountsUser *user)
{
        return USER (user)->locked;
}

static gint
user_real_get_password_mode (AccountsUser *user)
{
        return USER (user)->password_mode;
}

static const gchar *
user_real_get_password_hint (AccountsUser *user)
{
        return USER (user)->password_hint;
}

static gboolean
user_real_get_automatic_login (AccountsUser *user)
{
        return USER (user)->automatic_login;
}

static gboolean
user_real_get_system_account (AccountsUser *user)
{
        return USER (user)->system_account;
}

static void
user_finalize (GObject *object)
{
        User *user;

        user = USER (object);

        g_clear_pointer (&user->keyfile, g_key_file_unref);

        g_free (user->object_path);
        g_free (user->user_name);
        g_free (user->real_name);
        g_free (user->home_dir);
        g_free (user->shell);
        g_free (user->icon_file);
        g_free (user->default_icon_file);
        g_free (user->email);
        g_free (user->language);
        g_free (user->x_session);
        g_free (user->location);
        g_free (user->password_hint);

	if (user->login_history)
		g_variant_unref (user->login_history);

        if (G_OBJECT_CLASS (user_parent_class)->finalize)
                (*G_OBJECT_CLASS (user_parent_class)->finalize) (object);
}

static void
user_set_property (GObject      *object,
                   guint         param_id,
                   const GValue *value,
                   GParamSpec   *pspec)
{
        User *user = USER (object);

        switch (param_id) {
        case PROP_ACCOUNT_TYPE:
                user->account_type = g_value_get_int (value);
                break;
        case PROP_LANGUAGE:
                user->language = g_value_dup_string (value);
                break;
        case PROP_X_SESSION:
                user->x_session = g_value_dup_string (value);
                break;
        case PROP_EMAIL:
                user->email = g_value_dup_string (value);
                break;
        case PROP_LOGIN_FREQUENCY:
                user->login_frequency = g_value_get_uint64 (value);
                break;
        case PROP_LOGIN_TIME:
                user->login_time = g_value_get_int64 (value);
                break;
        case PROP_LOGIN_HISTORY:
                if (user->login_history)
                        g_variant_unref (user->login_history);
                user->login_history = g_variant_ref (g_value_get_variant (value));
                break;
        case PROP_AUTOMATIC_LOGIN:
                user->automatic_login = g_value_get_boolean (value);
                break;
        case PROP_SYSTEM_ACCOUNT:
                user->system_account = g_value_get_boolean (value);
                break;
        default:
                G_OBJECT_WARN_INVALID_PROPERTY_ID (object, param_id, pspec);
                break;
        }
}

static void
user_get_property (GObject    *object,
                   guint       param_id,
                   GValue     *value,
                   GParamSpec *pspec)
{
        User *user = USER (object);

        switch (param_id) {
        case PROP_UID:
                g_value_set_uint64 (value, user->uid);
                break;
        case PROP_USER_NAME:
                g_value_set_string (value, user->user_name);
                break;
        case PROP_REAL_NAME:
                g_value_set_string (value, user->real_name);
                break;
        case PROP_ACCOUNT_TYPE:
                g_value_set_int (value, user->account_type);
                break;
        case PROP_PASSWORD_MODE:
                g_value_set_int (value, user->password_mode);
                break;
        case PROP_PASSWORD_HINT:
                g_value_set_string (value, user->password_hint);
                break;
        case PROP_HOME_DIR:
                g_value_set_string (value, user->home_dir);
                break;
        case PROP_SHELL:
                g_value_set_string (value, user->shell);
                break;
        case PROP_EMAIL:
                g_value_set_string (value, user->email);
                break;
        case PROP_LANGUAGE:
                g_value_set_string (value, user->language);
                break;
        case PROP_X_SESSION:
                g_value_set_string (value, user->x_session);
                break;
        case PROP_LOCATION:
                g_value_set_string (value, user->location);
                break;
        case PROP_ICON_FILE:
                if (user->icon_file)
                        g_value_set_string (value, user->icon_file);
                else {
                        gchar *icon_file;

                        icon_file = g_build_filename (user->home_dir, ".face", NULL);
                        g_value_take_string (value, icon_file);
                }
                break;
        case PROP_LOGIN_FREQUENCY:
                g_value_set_uint64 (value, user->login_frequency);
                break;
        case PROP_LOGIN_TIME:
                g_value_set_int64 (value, user->login_time);
                break;
        case PROP_LOGIN_HISTORY:
                g_value_set_variant (value, user->login_history);
                break;
        case PROP_LOCKED:
                g_value_set_boolean (value, user->locked);
                break;
        case PROP_AUTOMATIC_LOGIN:
                g_value_set_boolean (value, user->automatic_login);
                break;
        case PROP_SYSTEM_ACCOUNT:
                g_value_set_boolean (value, user->system_account);
                break;
        case PROP_LOCAL_ACCOUNT:
                g_value_set_boolean (value, user->local_account);
                break;
        default:
                G_OBJECT_WARN_INVALID_PROPERTY_ID (object, param_id, pspec);
                break;
        }
}

static void
user_class_init (UserClass *class)
{
        GObjectClass *gobject_class;

        gobject_class = G_OBJECT_CLASS (class);

        gobject_class->get_property = user_get_property;
        gobject_class->set_property = user_set_property;
        gobject_class->finalize = user_finalize;

        accounts_user_override_properties (gobject_class, 1);
}

static void
user_accounts_user_iface_init (AccountsUserIface *iface)
{
        iface->handle_set_account_type = user_set_account_type;
        iface->handle_set_automatic_login = user_set_automatic_login;
        iface->handle_set_email = user_set_email;
        iface->handle_set_home_directory = user_set_home_directory;
        iface->handle_set_icon_file = user_set_icon_file;
        iface->handle_set_language = user_set_language;
        iface->handle_set_location = user_set_location;
        iface->handle_set_locked = user_set_locked;
        iface->handle_set_password = user_set_password;
        iface->handle_set_password_mode = user_set_password_mode;
        iface->handle_set_password_hint = user_set_password_hint;
        iface->handle_set_real_name = user_set_real_name;
        iface->handle_set_shell = user_set_shell;
        iface->handle_set_user_name = user_set_user_name;
        iface->handle_set_xsession = user_set_x_session;
        iface->handle_get_password_expiration_policy = user_get_password_expiration_policy;
        iface->get_uid = user_real_get_uid;
        iface->get_user_name = user_real_get_user_name;
        iface->get_real_name = user_real_get_real_name;
        iface->get_account_type = user_real_get_account_type;
        iface->get_home_directory = user_real_get_home_directory;
        iface->get_shell = user_real_get_shell;
        iface->get_email = user_real_get_email;
        iface->get_language = user_real_get_language;
        iface->get_xsession = user_real_get_xsession;
        iface->get_location = user_real_get_location;
        iface->get_login_frequency = user_real_get_login_frequency;
        iface->get_login_time = user_real_get_login_time;
        iface->get_login_history = user_real_get_login_history;
        iface->get_icon_file = user_real_get_icon_file;
        iface->get_locked = user_real_get_locked;
        iface->get_password_mode = user_real_get_password_mode;
        iface->get_password_hint = user_real_get_password_hint;
        iface->get_automatic_login = user_real_get_automatic_login;
        iface->get_system_account = user_real_get_system_account;
}

static void
user_init (User *user)
{
        user->system_bus_connection = NULL;
        user->object_path = NULL;
        user->user_name = NULL;
        user->real_name = NULL;
        user->account_type = ACCOUNT_TYPE_STANDARD;
        user->home_dir = NULL;
        user->shell = NULL;
        user->icon_file = NULL;
        user->default_icon_file = NULL;
        user->email = NULL;
        user->language = NULL;
        user->x_session = NULL;
        user->location = NULL;
        user->password_mode = PASSWORD_MODE_REGULAR;
        user->password_hint = NULL;
        user->locked = FALSE;
        user->automatic_login = FALSE;
        user->system_account = FALSE;
        user->login_history = NULL;
        user->keyfile = g_key_file_new ();
}
