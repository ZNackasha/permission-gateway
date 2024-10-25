use std::sync::Arc;

use crate::{
    config::{self, Permission},
    session::Session,
};

use anyhow::Result;

pub async fn get_user_permissions<'a>(
    session: &Session,
    config: &'a Arc<config::Config>,
) -> Result<Vec<Permission>> {
    let response = reqwest::Client::new()
        .get(config.permission_url.to_string())
        .header(
            "cookie",
            format!(
                "{}={}; {}={}",
                config.access_token_jwt_cookie_name,
                session.get_access_jwt().get_full_token(),
                config.refresh_token_jwt_cookie_name,
                session.get_access_jwt().get_full_token()
            ),
        )
        .send()
        .await?;

    let text = response.text().await?;

    Ok(serde_json::from_str(&text)?)
}
