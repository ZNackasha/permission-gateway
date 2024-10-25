use hyper::Uri;

use crate::utils;

use anyhow::{anyhow, Result};

pub fn extract_socket_key_from_utl(url: &Uri, encryption_key: &str) -> Result<String> {
    let query = url.query().unwrap_or("");

    // split query by & and then by =
    let key_values = query.split("&").collect::<Vec<&str>>();

    // find key in keyValues
    let key = key_values
        .iter()
        .find(|&&x| x.starts_with("websocket_key="))
        .ok_or(anyhow!("Socket Key not Found"))?;

    // get the key value
    let key = key.split("=").collect::<Vec<&str>>()[1];

    // check if the key is empty

    Some(key)
        .filter(|s| !s.is_empty())
        .map_or(Err(anyhow!("invalid Socket key")), |s| {
            let uuid = s.split('.').nth(0).ok_or(anyhow!("invalid Socket key"))?;
            let hash = utils::cypher_hash_string(uuid, encryption_key);
            if hash == s {
                Ok(uuid.to_string())
            } else {
                Err(anyhow!("invalid Socket key"))
            }
        })
}
