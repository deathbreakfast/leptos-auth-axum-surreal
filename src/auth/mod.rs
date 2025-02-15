use leptos::prelude::*;

#[server(Login, "/api")]
pub async fn login(
    username: String,
    password: String,
    remember: Option<String>,
) -> Result<(), ServerFnError> {
    use self::ssr::*;
    use crate::user::*;

    let db = db()?;
    let auth = auth()?;

    let user: User = User::get_from_username(username, &db)
        .await
        .ok_or_else(|| ServerFnError::new("User does not exist."))?;

    let is_verified = user.verify(password, &db).await;

    if is_verified {
        auth.login_user(user.user_id as i64);
        auth.remember_user(remember.is_some());
        leptos_axum::redirect("/");
        return Ok(());
    }
    Err(ServerFnError::ServerError(
        "Password does not match.".to_string(),
    ))
}

#[server(Signup, "/api")]
pub async fn signup(
    username: String,
    password: String,
    password_confirmation: String,
    remember: Option<String>,
) -> Result<(), ServerFnError> {
    use self::ssr::*;
    use crate::user::ssr::*;
    pub use bcrypt::{hash, DEFAULT_COST};

    let db = db()?;
    let auth = auth()?;

    if password != password_confirmation {
        return Err(ServerFnError::ServerError(
            "Passwords did not match.".to_string(),
        ));
    }

    let password_hashed = hash(password, DEFAULT_COST).unwrap();

    let id = surrealdb::sql::Id::rand().to_raw();

    // Should probably drop and only use record ids
    let user_id = rand::random::<i64>();    

    let user: Result<Option<SurrealUser>, surrealdb::Error> = db
        .create(("users", &id))
        .content(SurrealUser {
            user_id: user_id,
            anonymous: false,
            password: password_hashed,
            username: username.clone(),
        })
        .await;
    let _: Result<Option<SurrealPermissionTokens>, surrealdb::Error> = db
        .create("user_permissions")
        .content(SurrealPermissionTokens {
            token: "Category::View".to_string(),
            user_id: user_id,
        })
        .await;
    let _: Result<Option<SurrealPermissionTokens>, surrealdb::Error> = db
        .create("user_permissions")
        .content(SurrealPermissionTokens {
            token: "Category::Edit".to_string(),
            user_id: user_id,
        })
        .await;

    if user.is_ok() {
        auth.login_user(user_id);
        auth.remember_user(remember.is_some());
        leptos_axum::redirect("/");
        Ok(())
    } else {
        Err(ServerFnError::ServerError(
            "User already exists.".to_string(),
        ))
    }
}

#[server(Logout, "/api")]
pub async fn logout() -> Result<(), ServerFnError> {
    use self::ssr::*;

    let auth = auth()?;
    auth.logout_user();
    leptos_axum::redirect("/");
    Ok(())
}

#[cfg(feature = "ssr")]
pub mod ssr {
    use crate::user::*;
    use async_trait::async_trait;
    use axum_session_auth::*;
    use axum_session_surreal::SessionSurrealPool;
    use leptos::prelude::*;
    use surrealdb::{engine::any::Any, Surreal};

    pub type SurrealAuthSession = AuthSession<User, i64, SessionSurrealPool<Any>, Surreal<Any>>;

    #[async_trait]
    impl Authentication<User, i64, Surreal<Any>> for User {
        async fn load_user(
            userid: i64,
            pool: Option<&Surreal<Any>>,
        ) -> Result<User, anyhow::Error> {
            let pool = pool.unwrap();

            User::get_user(userid, pool)
                .await
                .ok_or_else(|| anyhow::anyhow!("Could not load user"))
        }

        fn is_authenticated(&self) -> bool {
            !self.anonymous
        }

        fn is_active(&self) -> bool {
            !self.anonymous
        }

        fn is_anonymous(&self) -> bool {
            self.anonymous
        }
    }

    #[async_trait]
    impl HasPermission<Surreal<Any>> for User {
        async fn has(&self, perm: &str, _pool: &Option<&Surreal<Any>>) -> bool {
            self.permissions.contains(perm)
        }
    }

    // This returns None on page load
    pub fn auth() -> Result<SurrealAuthSession, ServerFnError> {
        use_context::<SurrealAuthSession>()
            .ok_or_else(|| ServerFnError::ServerError("AuthSession not found.".into()))
    }

    pub fn db() -> Result<Surreal<Any>, ServerFnError> {
        use_context::<Surreal<Any>>()
            .ok_or_else(|| ServerFnError::ServerError("AuthSession not found.".into()))
    }
}
