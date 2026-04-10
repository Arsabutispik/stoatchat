use revolt_database::{util::reference::Reference, AdminAuthorization, Database};
use revolt_models::v0::{self};
use revolt_result::{create_error, Result};
use rocket::{serde::json::Json, State};

use crate::routes::admin::util::{
    create_audit_action, flatten_authorized_user, user_has_permission,
};

/// Get a list of admin users. Any active user may use this endpoint.
/// Typically the client should cache this data.
#[openapi(tag = "Admin")]
#[get("/servers/<id>?<case>")]
pub async fn admin_server_get(
    db: &State<Database>,
    auth: AdminAuthorization,
    id: Reference<'_>,
    case: Option<&str>,
) -> Result<Json<v0::AdminServerResponse>> {
    let user = flatten_authorized_user(&auth);
    if !user_has_permission(user, v0::AdminUserPermissionFlags::ManageServers) {
        return Err(create_error!(MissingPermission {
            permission: "ManageServers".to_string()
        }));
    }

    let server = id.as_server(db).await?;
    let owner = db.fetch_user(&server.owner).await?.into_self(false).await;
    let comments: Vec<v0::AdminComment> = db
        .admin_comment_fetch_object_comments(&server.id)
        .await?
        .iter()
        .map(|f| f.clone().into())
        .collect();

    create_audit_action(
        db,
        &user.id,
        v0::AdminAuditItemActions::ServerFetch,
        case,
        Some(&id.id),
        None,
    )
    .await?;

    Ok(Json(v0::AdminServerResponse {
        server: server.into(),
        owner,
        comments,
    }))
}
