use leptos::prelude::*;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserRecord {
    pub id: String,
    pub anonymous: bool,
    pub username: String,
    #[serde(skip)]
    pub permissions: HashSet<String>,
}

impl Default for UserRecord {
    fn default() -> Self {
        let mut permissions = HashSet::new();
        permissions.insert("Category::View".to_owned());

        Self {
            id: "1".into(),
            anonymous: true,
            username: "Guest".into(),
            permissions,
        }
    }
}

#[server(CurrentUser, "/api")]
pub async fn current_user() -> Result<Option<UserRecord>, ServerFnError> {
    use crate::auth::ssr::*;
    let auth = auth();
    if auth.is_err() {
        return Ok(None);
    }
    Ok(Some(auth.unwrap().current_user.unwrap_or_default()))
}

#[cfg(feature = "ssr")]
pub mod ssr {
    use crate::user::UserRecord;
    use bcrypt::{hash, DEFAULT_COST};
    use serde::{Deserialize, Serialize};
    use std::collections::HashSet;
    use surrealdb::{engine::any::Any, RecordId, Surreal};

    #[derive(Debug, Serialize, Deserialize, Clone)]
    pub struct PermissionTokens {
        pub token: String,
    }

    #[derive(Debug, Serialize, Deserialize, Clone)]
    pub struct SurrealPermissionTokens {
        pub token: String,
        pub user_id: RecordId,
    }

    impl UserRecord {
        pub fn has_permission(&self, token: &str) -> bool {
            self.permissions.contains(token)
        }

        pub async fn verify(&self, db: &Surreal<Any>, password: String) -> bool {
            let surreal_user: Option<SurrealUserRecord> = db
                .query("SELECT id, username, password, anonymous FROM users where username = $username")
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

        pub async fn get_user(db: &Surreal<Any>, user_id: String) -> Option<Self> {
            let surreal_user: Option<SurrealUserRecord> =
                db.select(("users", user_id.clone())).await.unwrap();
            if surreal_user.is_none() {
                return None;
            }

            //lets just get all the tokens the user can use, we will only use the full permissions if modifing them.
            let surreal_user_perms: Vec<PermissionTokens> = db
                .query("SELECT token FROM user_permissions where user_id = $user_id")
                .bind(("user_id", RecordId::from_table_key("users", user_id)))
                .await
                .unwrap()
                .take(0)
                .unwrap();

            Some(surreal_user.unwrap().into_user(Some(surreal_user_perms)))
        }

        pub async fn get_from_username(db: &Surreal<Any>, username: String) -> Option<Self> {
            let surreal_user: Option<SurrealUserRecord> = db
                .query("SELECT id, username, password, anonymous FROM users where username = $username")
                .bind(("username", username.clone()))
                .await
                .unwrap()
                .take(0)
                .unwrap();

            if surreal_user.is_none() {
                return None;
            }

            //lets just get all the tokens the user can use, we will only use the full permissions if modifing them.
            let surreal_user_perms: Vec<PermissionTokens> = db
                .query("SELECT token FROM user_permissions where user_id = $user_id")
                .bind(("user_id", surreal_user.as_ref().unwrap().id.clone()))
                .await
                .unwrap()
                .take(0)
                .unwrap();

            Some(surreal_user.unwrap().into_user(Some(surreal_user_perms)))
        }

        pub async fn create_user_tables(db: &Surreal<Any>) {
            db.query(
                "   DEFINE TABLE users SCHEMAFULL; 
                DEFINE FIELD username ON TABLE users TYPE string;
                DEFINE FIELD password ON TABLE users TYPE string;
                DEFINE FIELD anonymous ON TABLE users TYPE bool;
            ",
            )
            .await
            .unwrap();

            db.query(
                "   DEFINE TABLE user_permissions SCHEMAFULL; 
                DEFINE FIELD token ON TABLE user_permissions TYPE string;
                DEFINE FIELD user_id ON TABLE user_permissions TYPE record;
            ",
            )
            .await
            .unwrap();

            // Check if guest user exists, if not create it.
            let user_id = RecordId::from_table_key::<&str, String>("users", "1".into());
            let user: Option<UserRecord> = UserRecord::get_user(db, "1".into()).await;
            if user.is_none() {
                let _: Result<Option<SurrealUserRecord>, surrealdb::Error> = db
                    .create("users")
                    .content(SurrealUserRecord {
                        id: user_id.clone(),
                        anonymous: true,
                        password: hash("".to_string(), DEFAULT_COST).unwrap(),
                        username: "Guest".to_string(),
                    })
                    .await;
                let _: Result<Option<SurrealPermissionTokens>, surrealdb::Error> = db
                    .create("user_permissions")
                    .content(SurrealPermissionTokens {
                        token: "Category::View".to_string(),
                        user_id: user_id,
                    })
                    .await;
            }

            // Check if default test user exists, if not create it.
            let user_id = RecordId::from_table_key::<&str, String>("users", "2".into());
            let user: Option<UserRecord> = UserRecord::get_user(db, "2".into()).await;
            if user.is_none() {
                let _: Result<Option<SurrealUserRecord>, surrealdb::Error> = db
                    .create("users")
                    .content(SurrealUserRecord {
                        id: user_id.clone(),
                        anonymous: false,
                        password: hash("password".to_string(), DEFAULT_COST).unwrap(),
                        username: "Test".to_string(),
                    })
                    .await;
                let _: Result<Option<SurrealPermissionTokens>, surrealdb::Error> = db
                    .create("user_permissions")
                    .content(SurrealPermissionTokens {
                        token: "Category::View".to_string(),
                        user_id: user_id.clone(),
                    })
                    .await;
                let _: Result<Option<SurrealPermissionTokens>, surrealdb::Error> = db
                    .create("user_permissions")
                    .content(SurrealPermissionTokens {
                        token: "Category::Edit".to_string(),
                        user_id: user_id,
                    })
                    .await;
            }
        }
    }

    #[derive(Debug, Serialize, Deserialize, Clone)]
    pub struct SurrealUserRecord {
        pub id: RecordId,
        pub anonymous: bool,
        pub password: String,
        pub username: String,
    }

    impl SurrealUserRecord {
        pub fn into_user(
            self,
            surreal_user_perms: Option<Vec<PermissionTokens>>,
        ) -> UserRecord {
            let id = self.id.key().to_string();
            let mut id = id.chars();
            id.next();
            id.next_back();
            UserRecord {
                id: id.as_str().to_string(),
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
