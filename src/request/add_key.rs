use crate::jwt::Jwt;
use anyhow::{anyhow, Result};
use http_body_util::Full;
use hyper::{body::Bytes, Request, Response};
use std::sync::Arc;
use std::time::Duration;
use tokio::time::timeout;

use crate::{config, sessions, utils};

fn get_key_from_permission(
    user_permission: &Vec<&String>,
    user_sessions: &Arc<sessions::SafeSessions>,
    req: &Request<hyper::body::Incoming>,
    jwt: &Jwt,
    config: &Arc<config::Config>,
) -> Result<Response<Full<Bytes>>> {
    if user_permission.len() == 0 {
        return Err(anyhow!(
            "You do not seem to have the permission to access this service",
        ));
    }

    // Extract the key from the query parameters if there is one
    let key = super::utils::extract_uuid_from_utl(req.uri(), &config.encryption_key);

    let user = match key {
        Ok(key) => user_sessions.get(&key)?,
        Err(_) => None,
    };

    let uuid = user.as_ref().map_or(utils::generate_uuid(), |user| {
        user.read()
            .map_or(utils::generate_uuid(), |f| f.uuid.clone())
    });

    let hash = Arc::new(utils::cypher_hash_string(&uuid, &config.encryption_key));

    user_sessions.insert(
        hash.to_string(),
        sessions::SessionInsert {
            uuid: uuid.clone(),
            hash: hash.to_string(),
            exp: jwt.get_payload().exp,
            server_ws_stream: user.as_ref().map_or(None, |u| {
                u.read().map_or(None, |f| f.server_ws_stream.clone())
            }),
            permissions: user_permission.clone(),
            client_ws_stream: user.as_ref().map_or(None, |u| {
                u.read().map_or(None, |f| f.client_ws_stream.clone())
            }),
        },
    )?;

    let spawn_hash = hash.clone();
    let exp = jwt.get_payload().exp.clone();
    let user_sessions = user_sessions.clone();
    tokio::spawn(async move {
        let _ = timeout(
            Duration::from_secs(exp - utils::get_current_unix_timestamp()),
            async {
                user_sessions
                    .get(spawn_hash.as_str())
                    .ok()
                    .and_then(|user| user)
                    .filter(|user| {
                        user.read().map_or(0, |u| u.exp) < utils::get_current_unix_timestamp()
                    })
                    .map(|_| user_sessions.remove(spawn_hash.as_str()));
            },
        )
        .await;
    });

    Ok(Response::new(Full::new(Bytes::from(
        (uuid.clone() + "." + hash.as_str()).to_string(),
    ))))
}
