use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use leptos::prelude::*;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    pub user_id: i64,
    pub anonymous: bool,
    pub username: String,
    #[serde(skip)]
    pub permissions: HashSet<String>,
}

impl Default for User {
    fn default() -> Self {
        let mut permissions = HashSet::new();

        permissions.insert("Category::View".to_owned());

        Self {
            user_id: 1,
            anonymous: true,
            username: "Guest".into(),
            permissions,
        }
    }
}

#[server(CurrentUser, "/api")]
pub async fn current_user() -> Result<Option<User>, ServerFnError> {
    use crate::auth::ssr::*;
    let auth = auth();
    if auth.is_err() {
        return Ok(None);
    }
    Ok(Some(auth.unwrap().current_user.unwrap_or_default()))
}

#[cfg(feature = "ssr")]
pub mod ssr {
    use crate::user::User;
    use serde::{Deserialize, Serialize};
    use std::collections::HashSet;
    use surrealdb::{engine::any::Any, Surreal};
    use bcrypt::{hash, DEFAULT_COST};

    #[derive(Debug, Serialize, Deserialize, Clone)]
    pub struct PermissionTokens {
        pub token: String,
    }

    #[derive(Debug, Serialize, Deserialize, Clone)]
    pub struct SurrealPermissionTokens {
        pub token: String,
        pub user_id: i64,
    }

    impl User {
        pub fn has_permission(&self, token: &str) -> bool {
            self.permissions.contains(token)
        }

        pub async fn verify(&self, password: String, pool: &Surreal<Any>) -> bool {
            let surreal_user: Option<SurrealUser> = pool
                .query("SELECT username, password, user_id, anonymous FROM users where username = $username")
                .bind(("username", self.username.clone()))
                .await
                .unwrap()
                .take(0)
                .unwrap();
            

            if let Some(surreal_user) = surreal_user {
                if bcrypt::verify(password, &surreal_user.password).unwrap() {
                    return true;
                }
            }
            false
        }

        pub async fn get_user(id: i64, pool: &Surreal<Any>) -> Option<Self> {
            let surreal_user: Option<SurrealUser> = pool
                .query("SELECT username, password, user_id, anonymous FROM users where user_id = $user_id")
                .bind(("user_id", id))
                .await
                .unwrap()
                .take(0)
                .unwrap();

            if surreal_user.is_none() {
                return None;
            }

            //lets just get all the tokens the user can use, we will only use the full permissions if modifing them.
            let surreal_user_perms: Vec<PermissionTokens> = pool
                .query("SELECT token FROM user_permissions where user_id = $user_id")
                .bind(("user_id", id))
                .await
                .unwrap()
                .take(0)
                .unwrap();

            Some(surreal_user.unwrap().into_user(Some(surreal_user_perms)))
        }

        pub async fn get_from_username(username: String, pool: &Surreal<Any>) -> Option<Self> {
            let surreal_user: Option<SurrealUser> = pool
                .query("SELECT username, password, user_id, anonymous FROM users where username = $username")
                .bind(("username", username.clone()))
                .await
                .unwrap()
                .take(0)
                .unwrap();
            
            if surreal_user.is_none() {
                return None;
            }

            //lets just get all the tokens the user can use, we will only use the full permissions if modifing them.
            let surreal_user_perms: Vec<PermissionTokens> = pool
                .query("SELECT token FROM user_permissions where user_id = $user_id")
                .bind(("user_id", surreal_user.as_ref().unwrap().user_id))
                .await
                .unwrap()
                .take(0)
                .unwrap();

            Some(surreal_user.unwrap().into_user(Some(surreal_user_perms)))
        }

        pub async fn create_user_tables(pool: &Surreal<Any>) {
            pool.query(
                "   DEFINE TABLE users SCHEMAFULL; 
                DEFINE FIELD username ON TABLE users TYPE string;
                DEFINE FIELD password ON TABLE users TYPE string;
                DEFINE FIELD anonymous ON TABLE users TYPE bool;
                DEFINE FIELD user_id ON TABLE users TYPE int;
            ",
            )
            .await
            .unwrap();

            pool.query(
                "   DEFINE TABLE user_permissions SCHEMAFULL; 
                DEFINE FIELD token ON TABLE user_permissions TYPE string;
                DEFINE FIELD user_id ON TABLE user_permissions TYPE int;
            ",
            )
            .await
            .unwrap();
            
            // Check if guest user exists, if not create it.
            let user: Option<User> = User::get_user(1, pool).await;
            if user.is_none() {
                let _: Result<Option<SurrealUser>, surrealdb::Error> = pool
                    .create("users")
                    .content(SurrealUser {
                        user_id: 1,
                        anonymous: true,
                        password: hash("".to_string(), DEFAULT_COST).unwrap(),
                        username: "Guest".to_string(),
                    })
                    .await;
                let _: Result<Option<SurrealPermissionTokens>, surrealdb::Error> = pool
                    .create("user_permissions")
                    .content(SurrealPermissionTokens {
                        token: "Category::View".to_string(),
                        user_id: 1,
                    })
                    .await;
            }

            // Check if default test user exists, if not create it.
            let user: Option<User> = User::get_user(2, pool).await;
            if user.is_none() {
                let _: Result<Option<SurrealUser>, surrealdb::Error> = pool
                    .create("users")
                    .content(SurrealUser {
                        user_id: 2,
                        anonymous: false,
                        password: hash("password".to_string(), DEFAULT_COST).unwrap(),
                        username: "Test".to_string(),
                    })
                    .await;
                let _: Result<Option<SurrealPermissionTokens>, surrealdb::Error> = pool
                    .create("user_permissions")
                    .content(SurrealPermissionTokens {
                        token: "Category::View".to_string(),
                        user_id: 2,
                    })
                    .await;
                let _: Result<Option<SurrealPermissionTokens>, surrealdb::Error> = pool
                    .create("user_permissions")
                    .content(SurrealPermissionTokens {
                        token: "Category::Edit".to_string(),
                        user_id: 2,
                    })
                    .await;
            }
        }
    }

    #[derive(Debug, Serialize, Deserialize, Clone)]
    pub struct SurrealUser {
        pub user_id: i64,
        pub anonymous: bool,
        pub password: String,
        pub username: String,
    }

    impl SurrealUser {
        pub fn into_user(self, surreal_user_perms: Option<Vec<PermissionTokens>>) -> User {
            User {
                user_id: self.user_id,
                anonymous: self.anonymous,
                username: self.username,
                permissions: if let Some(user_perms) = surreal_user_perms {
                    user_perms
                        .into_iter()
                        .map(|x| x.token)
                        .collect::<HashSet<String>>()
                } else {
                    HashSet::<String>::new()
                },
            }
        }
    }
}
