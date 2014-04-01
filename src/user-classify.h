/*
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
 * Author: Ryan Lortie <desrt@desrt.ca>
 */

#ifndef __USER_CLASSIFY_H__
#define __USER_CLASSIFY_H__

#include <sys/types.h>
#include <glib.h>

gboolean        user_classify_is_human          (uid_t        uid,
                                                 const gchar *username,
                                                 const gchar *shell,
                                                 const gchar *password_hash);

#endif /* __USER_CLASSIFY_H__ */
