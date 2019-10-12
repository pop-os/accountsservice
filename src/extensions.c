/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*-
 *
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
 * Written by: Ryan Lortie <desrt@desrt.ca>
 */

#include "config.h"

#include "daemon.h"

#include <gio/gio.h>
#include <string.h>

static void
daemon_maybe_add_extension_interface (GHashTable         *ifaces,
                                      GDBusInterfaceInfo *iface)
{
        gint i;

        /* We visit the XDG data dirs in precedence order, so if we
         * already have this one, we should not add it again.
         */
        if (g_hash_table_contains (ifaces, iface->name))
                return;

        /* Only accept interfaces with only properties */
        if ((iface->methods && iface->methods[0]) || (iface->signals && iface->signals[0]))
                return;

        /* Add it only if we can find the annotation */
        for (i = 0; iface->annotations && iface->annotations[i]; i++) {
                if (g_str_equal (iface->annotations[i]->key, "org.freedesktop.Accounts.VendorExtension")) {
                        g_hash_table_insert (ifaces, g_strdup (iface->name), g_dbus_interface_info_ref (iface));
                        return;
                }
        }
}

static void
daemon_read_extension_file (GHashTable  *ifaces,
                            const gchar *filename)
{
        g_autoptr(GError) error = NULL;
        g_autoptr(GDBusNodeInfo) node = NULL;
        g_autofree gchar *contents = NULL;
        gint i;

        if (!g_file_get_contents (filename, &contents, NULL, &error)) {
                g_warning ("Unable to read extension file %s: %s.  Ignoring.", filename, error->message);
                return;
        }

        node = g_dbus_node_info_new_for_xml (contents, &error);
        if (!node) {
                g_warning ("Failed to parse file %s: %s", filename, error->message);
                return;
        }

        for (i = 0; node->interfaces && node->interfaces[i]; i++)
                daemon_maybe_add_extension_interface (ifaces, node->interfaces[i]);
}

static void
daemon_read_extension_directory (GHashTable  *ifaces,
                                 const gchar *path)
{
        const gchar *name;
        GDir *dir;

        dir = g_dir_open (path, 0, NULL);
        if (!dir)
                return;

        while ((name = g_dir_read_name (dir))) {
                g_autofree gchar *filename = NULL;
                g_autofree gchar *symlink = NULL;

                /* Extensions are installed as normal D-Bus interface
                 * files with an annotation.
                 *
                 * D-Bus interface files are supposed to be installed in
                 * $(datadir)/dbus-1/interfaces/ but we don't want to
                 * scan all of the files there looking for interfaces
                 * that may contain our annotation.
                 *
                 * The solution is to install a symlink into a directory
                 * private to accountsservice and point it at the file,
                 * as installed in the usual D-Bus directory.
                 *
                 * This ensures compatibility with the future if we ever
                 * decide to check the interfaces directory directly
                 * (which might be a reasonable thing to do if we ever
                 * get an efficient cache of the contents of this
                 * directory).
                 *
                 * By introducing such a restrictive way of doing this
                 * now we ensure that everyone will do it in this
                 * forwards-compatible way.
                 */
                filename = g_build_filename (path, name, NULL);
                symlink = g_file_read_link (filename, NULL);

                if (!symlink) {
                        g_warning ("Found accounts service vendor extension file %s, but file must be a symlink to "
                                   "'../../dbus-1/interfaces/%s' for forwards-compatibility reasons.", filename, name);
                        continue;
                }

                /* Ensure it looks like "../../dbus-1/interfaces/${name}" */
                const gchar * const prefix = "../../dbus-1/interfaces/";
                if (g_str_has_prefix (symlink, prefix) && g_str_equal (symlink + strlen (prefix), name)) {
                        daemon_read_extension_file (ifaces, filename);
                }
                else {
                        g_warning ("Found accounts service vendor extension symlink %s, but it must be exactly "
                                   "equal to '../../dbus-1/interfaces/%s' for forwards-compatibility reasons.",
                                   filename, name);
                }
        }

        g_dir_close (dir);
}

GHashTable *
daemon_read_extension_ifaces (void)
{
        const gchar * const *data_dirs;
        GHashTable *ifaces;
        gint i;

        ifaces = g_hash_table_new_full (g_str_hash, g_str_equal, g_free, (GDestroyNotify) g_dbus_interface_info_unref);

        data_dirs = g_get_system_data_dirs ();
        for (i = 0; data_dirs[i]; i++) {
                g_autofree gchar *path = g_build_filename (data_dirs[i], "accountsservice/interfaces", NULL);
                daemon_read_extension_directory (ifaces, path);
        }

        return ifaces;
}
