use hyper::Uri;
use std::collections::HashMap;

use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize, Serialize, PartialEq)]
pub struct Permission {
    pub effect: String,
    pub action: String,
    pub resource: String,
}

pub struct Config {
    pub listening_address: String,

    pub permission_url: String,

    pub encryption_key: String,

    pub sidecar_url: Uri,

    pub jwt_cookie_name: String,

    pub permissions: HashMap<String, Vec<Vec<Permission>>>,
}
