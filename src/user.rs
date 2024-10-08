use std::sync::Arc;

use serde::{Deserialize, Serialize};

use crate::{
    config::{self, Permission},
    error::Error,
    jwt::Jwt,
};

#[derive(Debug, Serialize, Deserialize)]
struct Session {
    user: User,
}

#[derive(Debug, Serialize, Deserialize)]
struct User {
    permissions: Vec<Permission>,
}

async fn make_user_permissions_request(
    access_token: &str,
    config: &config::Config,
) -> Result<Vec<Permission>, Error> {
    let response = reqwest::Client::new()
        .get(config.permission_url.as_str())
        .header(
            "cookie",
            format!("{}={}", config.jwt_cookie_name, access_token),
        )
        .send()
        .await?;

    let text = response.text().await?;

    let json: Session = serde_json::from_str(&text)?;
    Ok(json.user.permissions)
}

async fn fetch_user_permissions<'a>(
    jwt: &Jwt<'a>,
    config: &'a Arc<config::Config>,
) -> Result<Vec<&'a String>, Error> {
    // get cookie from request

    let permissions = make_user_permissions_request(jwt.get_full_token(), &config).await?;

    // Check if the permissions are are in config.permissions
    Ok(config
        .permissions
        .iter()
        .filter_map(|(name, perms)| {
            if perms
                .iter()
                .any(|x| x.iter().all(|p| permissions.contains(&p)))
            {
                Some(name)
            } else {
                None
            }
        })
        .collect::<Vec<&String>>())
}

pub async fn get_user_permissions<'a>(
    user_sessions: &Arc<crate::sessions::SafeSessions>,
    jwt: &Jwt<'a>,
    config: &'a Arc<config::Config>,
) -> Result<Vec<&'a String>, Error> {
    fetch_user_permissions(jwt, config).await
}
