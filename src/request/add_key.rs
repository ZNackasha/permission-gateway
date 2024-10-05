use http_body_util::Full;
use hyper::{body::Bytes, Request, Response};
use std::sync::Arc;
use std::time::Duration;
use tokio::time::timeout;

use crate::{config, error::Error, sessions, user, utils};

async fn add_key_request(
    keys: Arc<sessions::SafeSessions>,
    req: &Request<hyper::body::Incoming>,
    config: Arc<config::Config>,
) -> Result<String, Error> {
    // get cookie from request
    let cookies = utils::get_cookies(&req);

    // get access tocken from cookies
    let access_token = user::get_access_token(cookies)?;

    // decode jwt access_token
    let access_token_payload = user::get_jwt_payload(access_token)?;

    if access_token_payload.exp < utils::get_current_unix_timestamp() {
        return Err(Error::from("access token expired"));
    }

    let permissions = user::get_user_permissions(access_token, &config.iam_url).await?;

    // Check if the permissions are are in config.permissions
    let user_permission: Vec<&String> = config
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
        .collect();

    if user_permission.len() == 0 || access_token_payload.exp < utils::get_current_unix_timestamp()
    {
        return Err(Error::from(
            "You do not seem to have the permission to access this service",
        ));
    }

    // Extract the key from the query parameters if there is one
    let key = super::utils::extract_uuid_from_utl(req.uri(), &config.encryption_key);

    let user = match key {
        Ok(key) => keys.get(&key)?,
        Err(_) => None,
    };

    let uuid = user.as_ref().map_or(utils::generate_uuid(), |user| {
        user.read()
            .map_or(utils::generate_uuid(), |f| f.uuid.clone())
    });

    let hash = Arc::new(utils::cypher_hash_string(&uuid, &config.encryption_key));

    keys.insert(
        hash.to_string(),
        sessions::SessionInsert {
            uuid: uuid.clone(),
            hash: hash.to_string(),
            exp: access_token_payload.exp,
            server_ws_stream: user.as_ref().map_or(None, |u| {
                u.read().map_or(None, |f| f.server_ws_stream.clone())
            }),
            permissions: user_permission,
            client_ws_stream: user.as_ref().map_or(None, |u| {
                u.read().map_or(None, |f| f.client_ws_stream.clone())
            }),
        },
    )?;

    let spawn_hash = hash.clone();
    tokio::spawn(async move {
        let _ = timeout(
            Duration::from_secs(access_token_payload.exp - utils::get_current_unix_timestamp()),
            async {
                keys.get(spawn_hash.as_str())
                    .ok()
                    .and_then(|user| user)
                    .filter(|user| {
                        user.read().map_or(0, |u| u.exp) < utils::get_current_unix_timestamp()
                    })
                    .map(|_| keys.remove(spawn_hash.as_str()));
            },
        )
        .await;
    });
    return Ok(uuid.clone() + "." + hash.as_str());
}

pub async fn handle_add_key(
    req: &Request<hyper::body::Incoming>,
    keys: Arc<sessions::SafeSessions>,
    config: Arc<config::Config>,
) -> Result<Response<Full<Bytes>>, Error> {
    Ok(Response::new(Full::new(Bytes::from(
        add_key_request(keys, &req, config)
            .await?
            .clone()
            .to_string(),
    ))))
}
