use std::sync::Arc;

use hyper::{Request, Uri};

use crate::{error::Error, sessions, utils};

pub fn request_has_valid_key(
    req: &Request<hyper::body::Incoming>,
    keys: Arc<sessions::SafeSessions>,
    encryption_key: &str,
) -> Result<(), Error> {
    // get the key from the query parameters
    let key = extract_uuid_from_utl(req.uri(), encryption_key)?;

    // Check if the key is valid
    let key = keys.get(&key);

    return match key {
        Ok(key) => key.ok_or(Error::from("Key is not valid")).map(|_| ()),
        Err(_) => Err(Error::from("Key is not valid")),
    };
}

pub fn extract_uuid_from_utl(url: &Uri, encryption_key: &str) -> Result<String, Error> {
    let query = url.query().unwrap_or("");

    // split query by & and then by =
    let key_values = query.split("&").collect::<Vec<&str>>();

    // find key in keyValues
    let key = key_values
        .iter()
        .find(|&&x| x.starts_with("key="))
        .ok_or(Error::from("Key not Found"))?;

    // get the key value
    let key = key.split("=").collect::<Vec<&str>>()[1];

    // check if the key is empty

    Some(key).filter(|s| !s.is_empty()).map_or_else(
        || Err(Error::from("invalid key")),
        |s| {
            let uuid = s.split('.').nth(0).ok_or(Error::from("invalid key"))?;
            let hash = utils::cypher_hash_string(uuid, encryption_key);
            if hash == s {
                return Ok(uuid.to_string());
            } else {
                return Err(Error::from("invalid key"));
            }
        },
    )
}
