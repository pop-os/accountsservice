


#include "act-user.h"
#include "act-user-manager.h"
#include "act-user-enum-types.h"
#include <glib-object.h>

/* enumerations from "act-user.h" */
GType
act_user_account_type_get_type (void)
{
  static GType etype = 0;
  if (etype == 0) {
    static const GEnumValue values[] = {
      { ACT_USER_ACCOUNT_TYPE_STANDARD, "ACT_USER_ACCOUNT_TYPE_STANDARD", "standard" },
      { ACT_USER_ACCOUNT_TYPE_ADMINISTRATOR, "ACT_USER_ACCOUNT_TYPE_ADMINISTRATOR", "administrator" },
      { 0, NULL, NULL }
    };
    etype = g_enum_register_static ("ActUserAccountType", values);
  }
  return etype;
}
GType
act_user_password_mode_get_type (void)
{
  static GType etype = 0;
  if (etype == 0) {
    static const GEnumValue values[] = {
      { ACT_USER_PASSWORD_MODE_REGULAR, "ACT_USER_PASSWORD_MODE_REGULAR", "regular" },
      { ACT_USER_PASSWORD_MODE_SET_AT_LOGIN, "ACT_USER_PASSWORD_MODE_SET_AT_LOGIN", "set-at-login" },
      { ACT_USER_PASSWORD_MODE_NONE, "ACT_USER_PASSWORD_MODE_NONE", "none" },
      { 0, NULL, NULL }
    };
    etype = g_enum_register_static ("ActUserPasswordMode", values);
  }
  return etype;
}

/* enumerations from "act-user-manager.h" */
GType
act_user_manager_error_get_type (void)
{
  static GType etype = 0;
  if (etype == 0) {
    static const GEnumValue values[] = {
      { ACT_USER_MANAGER_ERROR_FAILED, "ACT_USER_MANAGER_ERROR_FAILED", "failed" },
      { ACT_USER_MANAGER_ERROR_USER_EXISTS, "ACT_USER_MANAGER_ERROR_USER_EXISTS", "user-exists" },
      { ACT_USER_MANAGER_ERROR_USER_DOES_NOT_EXIST, "ACT_USER_MANAGER_ERROR_USER_DOES_NOT_EXIST", "user-does-not-exist" },
      { ACT_USER_MANAGER_ERROR_PERMISSION_DENIED, "ACT_USER_MANAGER_ERROR_PERMISSION_DENIED", "permission-denied" },
      { ACT_USER_MANAGER_ERROR_NOT_SUPPORTED, "ACT_USER_MANAGER_ERROR_NOT_SUPPORTED", "not-supported" },
      { 0, NULL, NULL }
    };
    etype = g_enum_register_static ("ActUserManagerError", values);
  }
  return etype;
}



