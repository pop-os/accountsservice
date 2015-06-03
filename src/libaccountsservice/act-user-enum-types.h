


#ifndef __ACT_USER_ENUM_TYPES_H__
#define __ACT_USER_ENUM_TYPES_H__

#include <glib-object.h>

G_BEGIN_DECLS
/* enumerations from "act-user.h" */
GType act_user_account_type_get_type (void);
#define ACT_USER_TYPE_USER_ACCOUNT_TYPE (act_user_account_type_get_type())
GType act_user_password_mode_get_type (void);
#define ACT_USER_TYPE_USER_PASSWORD_MODE (act_user_password_mode_get_type())
/* enumerations from "act-user-manager.h" */
GType act_user_manager_error_get_type (void);
#define ACT_USER_TYPE_USER_MANAGER_ERROR (act_user_manager_error_get_type())
G_END_DECLS

#endif /* __ACT_USER_ENUM_TYPES_H__ */



