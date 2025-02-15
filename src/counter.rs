use leptos::prelude::*;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Counter {
    pub count: i32,
}

impl Default for Counter {
    fn default() -> Self {
        Self { count: 0 }
    }
}

#[server(GetCount, "/api")]
pub async fn get_count() -> Result<Counter, ServerFnError> {
    use crate::auth::ssr::*;
    let db = db()?;

    let counter = Counter::get(&db).await.unwrap_or_default();
    Ok(counter)
}

#[server(BumpCount, "/api")]
pub async fn bump_count(bump_count: i32) -> Result<(), ServerFnError> {
    use crate::auth::ssr::*;
    let db = db()?;
    let auth = auth()?;
    let current_user = auth.current_user;

    if current_user.is_some() {
        if !current_user.clone().unwrap().has_permission("Category::Edit") {
            return Err(ServerFnError::new(
                "User does not have permission to update counter, make sure you are signed in.",
            ));
        }
        let count = Counter::get(&db).await.unwrap_or_default();
        count.add(&db, bump_count).await;
        return Ok(());
    }

    Err(ServerFnError::new("User not found, make sure you are signed in."))
}

#[cfg(feature = "ssr")]
pub mod ssr {
    use serde::{Deserialize, Serialize};
    use surrealdb::{engine::any::Any, Surreal};
    use crate::counter::Counter;

    impl Counter {
        pub async fn get(db: &Surreal<Any>) -> Option<Self> {
            let count: Option<Counter> = db
                .query("SELECT count FROM counters where name = $counter_name")
                .bind(("counter_name", "total"))
                .await
                .unwrap()
                .take(0)
                .unwrap();
            count
        }

        pub async fn add(self: &Self, db: &Surreal<Any>, count: i32) {
            db.query("UPDATE counters SET count = count + $count WHERE name = $counter_name")
                .bind(("count", count))
                .bind(("counter_name", "total"))
                .await
                .unwrap();
        }

        pub async fn create_counter_table(db: &Surreal<Any>) {
            db.query(
                "   DEFINE TABLE counters SCHEMAFULL; 
                DEFINE FIELD name ON TABLE counters TYPE string;
                DEFINE FIELD count ON TABLE counters TYPE int;
            ",
            )
            .await
            .unwrap();

            let counter: Option<Counter> = Counter::get(db).await;
            if counter.is_none() {
                let _: Result<Option<SurrealCounter>, surrealdb::Error> = db
                    .create("counters")
                    .content(SurrealCounter {
                        name: "total".to_string(),
                        count: 0,
                    })
                    .await;
            }
        }
    }

    #[derive(Debug, Serialize, Deserialize, Clone)]
    struct SurrealCounter {
        name: String,
        count: i32, 
    }
}
