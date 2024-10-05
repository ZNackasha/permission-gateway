use base64::prelude::*;
use serde::{Deserialize, Serialize};

use crate::{config::Permission, error::Error};

#[derive(Debug, Serialize, Deserialize)]
struct Session {
    user: User,
}

#[derive(Debug, Serialize, Deserialize)]
struct User {
    permissions: Vec<Permission>,
}

#[derive(Debug, Serialize, Deserialize, PartialEq)]
pub struct JwtPayload {
    pub token_type: String,
    pub exp: u64,
    pub iat: u64,
    pub jti: String,
    pub user_id: i32,
    pub iss: String,
}

pub async fn get_user_permissions(
    access_token: &str,
    iam_url: &str,
) -> Result<Vec<Permission>, Error> {
    let response = reqwest::Client::new()
        .get(iam_url)
        .header("cookie", String::from("bz_access=") + access_token)
        .send()
        .await?;

    let text = response.text().await?;

    let json: Session = serde_json::from_str(&text)?;
    Ok(json.user.permissions)
}

pub fn get_access_token<'a>(cookies: impl Iterator<Item = &'a str>) -> Result<&'a str, Error> {
    cookies
        .into_iter()
        .find(|x| x.starts_with("bz_access="))
        .map_or(None, |x| x.split('=').nth(1))
        .ok_or(Error::from("No key found"))
}

pub fn get_jwt_payload(access_token: &str) -> Result<JwtPayload, Error> {
    let parts: Vec<&str> = access_token.split('.').collect();
    let payload = BASE64_URL_SAFE_NO_PAD.decode(parts[1])?;
    let claims: JwtPayload = serde_json::from_slice(&payload)?;
    Ok(claims)
}

// test get_jwt_payload  generate test with token equal to eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJ0b2tlbl90eXBlIjoiYWNjZXNzIiwiZXhwIjoxNzA0NzcxNjQ3LCJpYXQiOjE3MDMyMTcxNjQsImp0aSI6IjRlZWU3YzI3MDM3NjRhMjU4NjY2NmNmYjZjYjUxOGE1IiwidXNlcl9pZCI6MjAxOTQ0LCJpc3MiOiJodHRwczovL3d3dy5iZW56aW5nYS5jb20ifQ.Xm9vSVoPW8itvWQzjCuR5WAjh1De0E6OybC7dQwEyMlavkZa9j5ySVyfUb4nJALuvU7MfihGfYVM01dDGTrREP1YJxfzJZm3f0xwA54QtH6qe4MzN-ADRoecIzzaSzKGohq3XbVGrtZl4uOp0CLTUKGdpXpjieYzSkySqVCjpwigWWZnYg3px6ErhEICvxxaND_2k7QApEwo8ks61mYW6MJ5Bf3sJcgReRupGRPEs1we1d8D1_euiBYdbdBcMgq-wPVqIbbFr3kcTJAh4VuFTawLrechrci6PDFoX-bN3PXjTyocQ1BJ8xFERGKwiJJGtYy958Q156g3_oS5Q5y4SQ
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_jwt_payload() {
        let access_token = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJ0b2tlbl90eXBlIjoiYWNjZXNzIiwiZXhwIjoxNzA0NzcxNjQ3LCJpYXQiOjE3MDMyMTcxNjQsImp0aSI6IjRlZWU3YzI3MDM3NjRhMjU4NjY2NmNmYjZjYjUxOGE1IiwidXNlcl9pZCI6MjAxOTQ0LCJpc3MiOiJodHRwczovL3d3dy5iZW56aW5nYS5jb20ifQ.Xm9vSVoPW8itvWQzjCuR5WAjh1De0E6OybC7dQwEyMlavkZa9j5ySVyfUb4nJALuvU7MfihGfYVM01dDGTrREP1YJxfzJZm3f0xwA54QtH6qe4MzN-ADRoecIzzaSzKGohq3XbVGrtZl4uOp0CLTUKGdpXpjieYzSkySqVCjpwigWWZnYg3px6ErhEICvxxaND_2k7QApEwo8ks61mYW6MJ5Bf3sJcgReRupGRPEs1we1d8D1_euiBYdbdBcMgq-wPVqIbbFr3kcTJAh4VuFTawLrechrci6PDFoX-bN3PXjTyocQ1BJ8xFERGKwiJJGtYy958Q156g3_oS5Q5y4SQ";

        let expected_payload = JwtPayload {
            token_type: String::from("access"),
            exp: 1704771647,
            iat: 1703217164,
            jti: String::from("4eee7c2703764a2586666cfb6cb518a5"),
            user_id: 201944,
            iss: String::from("https://www.benzinga.com"),
        };

        let result = get_jwt_payload(access_token);

        assert!(result.is_ok());
        assert_eq!(result.unwrap(), expected_payload);
    }
}
