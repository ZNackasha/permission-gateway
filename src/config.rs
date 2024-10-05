use std::collections::HashMap;

use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize, Serialize, PartialEq)]
pub struct Permission {
    pub effect: String,
    pub action: String,
    pub resource: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct Config {
    pub listening_address: String,
    pub iam_url: String,
    pub encryption_key: String,
    pub redirect_address: String,
    pub permissions: HashMap<String, Vec<Vec<Permission>>>,
}
