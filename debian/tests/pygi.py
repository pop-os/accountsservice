#!/usr/bin/python3

import os

import gi
gi.require_version('AccountsService', '1.0')

from gi.repository import AccountsService
from gi.repository import GLib

def dump_user(caption, user):
    print(caption + ':')

    while not user.props.is_loaded:
        GLib.MainContext.default().iteration(True)

    print('\taccount type:', user.get_account_type())
    # Don't show this in an autopkgtest log to reduce spam harvesting
    #print('\temail:', user.get_email())
    print('\thome:', user.get_home_dir())
    print('\ticon file:', user.get_icon_file())
    print('\tis loaded:', user.is_loaded())
    print('\tis local account:', user.is_local_account())
    print('\tis logged in anywhere:', user.is_logged_in_anywhere())
    print('\tis logged in:', user.is_logged_in())
    print('\tis system account:', user.is_system_account())
    print('\tlanguage:', user.get_language())
    print('\tlocation:', user.get_location())
    print('\tlocked:', user.get_locked())
    print('\tlogin frequency:', user.get_login_frequency())
    print('\tlogin time:', user.get_login_time())
    print('\tnumber of sessions anywhere:', user.get_num_sessions_anywhere())
    print('\tnumber of sessions:', user.get_num_sessions())
    # Don't show this in an autopkgtest log for obvious reasons
    #print('\tpassword hint:', user.get_password_hint())
    print('\tpassword mode:', user.get_password_mode())
    print('\tprimary session ID:', user.get_primary_session_id())
    print('\tsaved:', user.get_saved())
    print('\tsession type:', user.get_session_type())
    print('\tsession:', user.get_session())
    print('\tshell:', user.get_shell())
    print('\tuid:', user.get_uid())
    print('\tusername:', user.get_user_name())
    print('\tX session:', user.get_x_session())

if __name__ == '__main__':
    um = AccountsService.UserManager.get_default()

    while not um.props.is_loaded:
        GLib.MainContext.default().iteration(True)

    print("Can switch:", um.can_switch())
    print("Has multiple users:", um.props.has_multiple_users)

    me = um.get_user_by_id(os.getuid())
    dump_user('uid %d' % os.getuid(), me)

    root = um.get_user('root')
    dump_user('root', root)
