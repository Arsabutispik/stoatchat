use futures::future::join_all;
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
#[get("/servers/<id>/participants?<case>")]
pub async fn admin_server_get_participants(
    db: &State<Database>,
    auth: AdminAuthorization,
    id: Reference<'_>,
    case: Option<&str>,
) -> Result<Json<Vec<(v0::User, Option<v0::Member>)>>> {
    let user = flatten_authorized_user(&auth);
    if !user_has_permission(user, v0::AdminUserPermissionFlags::ManageServers) {
        return Err(create_error!(MissingPermission {
            permission: "ManageServers".to_string()
        }));
    }

    let server = id.as_server(db).await?;
    let participants = db.fetch_server_participants(&server.id).await?;

    create_audit_action(
        db,
        &user.id,
        v0::AdminAuditItemActions::ServerFetchParticipants,
        case,
        Some(&id.id),
        None,
    )
    .await?;

    println!("{:?}", &participants);

    let resp = join_all(participants.iter().map(|(u, m)| async move {
        let user: v0::User = u.clone().into_self(false).await;
        let member: Option<v0::Member> = m.clone().map(|mu| mu.into());
        (user, member)
    }))
    .await;

    Ok(Json(resp))
}
