use crate::routes::admin::util::{
    create_audit_action, flatten_authorized_user, user_has_permission,
};
use revolt_database::util::reference::Reference;
use revolt_database::{AdminAuthorization, Database};
use revolt_models::v0::{self};
use revolt_result::{create_error, Result};
use rocket::serde::json::Json;
use rocket::State;

/// Disable an account. Requires AccountDisable permissions
#[openapi(tag = "Admin")]
#[post("/accounts/disable/<id>")]
pub async fn admin_account_disable(
    db: &State<Database>,
    auth: AdminAuthorization,
    id: Reference<'_>,
) -> Result<()> {
    let user = flatten_authorized_user(&auth);
    if !user_has_permission(user, v0::AdminUserPermissionFlags::AccountDisable) {
        return Err(create_error!(MissingPermission {
            permission: "AccountDisable".to_string()
        }));
    }

    let target = id.as_user(db).await?;

    if target.privileged {
        return Err(create_error!(PrivilegedAccount));
    }

    let admin = db.admin_user_fetch(&target.id).await.ok();

    if let Some(admin) = admin {
        if user_has_permission(&admin, v0::AdminUserPermissionFlags::AccountDisable) {
            return Err(create_error!(PrivilegedAccount));
        }
    }

    create_audit_action(
        db,
        &user.id,
        v0::AdminAuditItemActions::AccountDisable,
        None,
        Some(id.id),
        None,
    )
    .await?;

    db.disable_authifier_account(&target.id).await?;

    Ok(())
}
