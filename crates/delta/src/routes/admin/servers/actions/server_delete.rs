use revolt_database::{util::reference::Reference, AdminAuthorization, Database};
use revolt_models::v0::{self};
use revolt_result::{create_error, Result};
use rocket::State;
use rocket_empty::EmptyResponse;

use crate::routes::admin::util::{
    create_audit_action, flatten_authorized_user, user_has_permission,
};

/// Get a list of admin users. Any active user may use this endpoint.
/// Typically the client should cache this data.
#[openapi(tag = "Admin")]
#[delete("/servers/<id>?<case>")]
pub async fn admin_server_delete(
    db: &State<Database>,
    auth: AdminAuthorization,
    id: Reference<'_>,
    case: Option<&str>,
) -> Result<EmptyResponse> {
    let user = flatten_authorized_user(&auth);
    if !user_has_permission(user, v0::AdminUserPermissionFlags::ManageServers) {
        return Err(create_error!(MissingPermission {
            permission: "ManageServers".to_string()
        }));
    }

    db.delete_server(&id.id).await?;

    create_audit_action(
        db,
        &user.id,
        v0::AdminAuditItemActions::ServerDelete,
        case,
        Some(&id.id),
        None,
    )
    .await?;

    Ok(EmptyResponse)
}
