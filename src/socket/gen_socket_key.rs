use anyhow::{anyhow, Result};
use http_body_util::Full;
use hyper::{body::Bytes, Response};
use std::sync::Arc;

use crate::{
    config,
    session::{Session, SocketSession},
    utils,
};

pub fn gen_socket_key(
    session: &Arc<std::sync::RwLock<Session>>,
    config: &Arc<config::Config>,
) -> Result<Response<Full<Bytes>>> {
    if session
        .read()
        .or(Err(anyhow!("could not read from RWLock")))?
        .get_permissions()
        .len()
        == 0
    {
        return Err(anyhow!(
            "You do not seem to have the permission to access this service",
        ));
    }

    let (uuid, hash) = session
        .read()
        .or(Err(anyhow!("could not read from RWLock")))?
        .get_socket_session()
        .map_or_else(
            || {
                let uuid = utils::generate_uuid();
                let hash = utils::cypher_hash_string(&uuid, &config.socket_encryption_key);
                (uuid, hash)
            },
            |user: &Arc<SocketSession>| (user.uuid.clone(), user.hash.clone()),
        );

    session
        .write()
        .or(Err(anyhow!("could not write from RWLock")))?
        .set_socket_session(uuid.clone(), hash.to_string());

    Ok(Response::new(Full::new(Bytes::from(
        (uuid.clone() + "." + hash.as_str()).to_string(),
    ))))
}
