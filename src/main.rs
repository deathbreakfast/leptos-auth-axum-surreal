mod auth;
mod counter;
mod user;

#[cfg(feature = "ssr")]
pub mod ssr {
    use axum::body::Body as AxumBody;
    use axum::extract::{FromRef, Path, State};
    use axum::{
        http::Request,
        response::{IntoResponse, Response},
    };
    use axum_session_surreal::SessionSurrealPool;
    use leptos::prelude::{provide_context, LeptosOptions};
    use leptos_axum::handle_server_fns_with_context;
    use leptos_auth_axum_surreal::app::*;
    use leptos_axum::AxumRouteListing;
    use surrealdb::{
        engine::any::Any,
        Surreal,
    };

    use crate::user::User;

    #[derive(FromRef, Debug, Clone)]
    pub struct AppState {
        /// Leptos requires you to have leptosOptions in your State struct for the leptos route handlers
        pub leptos_options: LeptosOptions,
        pub routes: Vec<AxumRouteListing>,
        pub db: Surreal<Any>,
    }

    pub async fn leptos_routes_handler(
        auth_session: axum_session_auth::AuthSession<
            User,
            i64,
            SessionSurrealPool<Any>,
            Surreal<Any>,
        >,
        state: State<AppState>,
        req: Request<AxumBody>,
    ) -> Response {
        let State(app_state) = state.clone();
        let handler = leptos_axum::render_route_with_context(
            state.routes.clone(),
            move || {
                provide_context(auth_session.clone());
                provide_context(app_state.db.clone());
            },
            move || shell(app_state.leptos_options.clone()),
        );
        handler(state, req).await.into_response()
    }

    pub async fn server_fn_handler(
        State(app_state): State<AppState>,
        auth_session: axum_session_auth::AuthSession<
            User,
            i64,
            SessionSurrealPool<Any>,
            Surreal<Any>,
        >,
        _path: Path<String>,
        request: Request<AxumBody>,
    ) -> impl IntoResponse {
        handle_server_fns_with_context(
            move || {
                provide_context(auth_session.clone());
                provide_context(app_state.db.clone());
            },
            request,
        )
        .await
    }
}

#[cfg(feature = "ssr")]
#[tokio::main]
async fn main() {
    use axum::{routing::get, Router};
    use axum_session::{SessionConfig, SessionLayer, SessionStore};
    use axum_session_auth::*;
    use axum_session_surreal::SessionSurrealPool;
    use leptos::logging::log;
    use leptos::prelude::*;
    use leptos_auth_axum_surreal::app::*;
    use leptos_axum::{generate_route_list, LeptosRoutes};
    use ssr::*;
    use surrealdb::{
        engine::any::{connect, Any},
        opt::auth::Root,
        Surreal,
    };
    use crate::user::User;
    use crate::counter::Counter;

    let db = connect("ws://localhost:8000").await.unwrap();

    // sign in as our account.
    db.signin(Root {
        username: "root",
        password: "root",
    })
    .await
    .unwrap();

    // Set the database and namespace we will function within.
    db.use_ns("test").use_db("test").await.unwrap();

    //This Defaults as normal Cookies.
    //To enable Private cookies for integrity, and authenticity please check the next Example.
    let session_config = SessionConfig::default().with_table_name("test_table");
    let auth_config = AuthConfig::<i64>::default().with_anonymous_user_id(Some(1));

    // create SessionStore and initiate the database tables
    let session_store: SessionStore<SessionSurrealPool<Any>> =
        SessionStore::new(Some(db.clone().into()), session_config)
            .await
            .unwrap();

    User::create_user_tables(&db).await;
    Counter::create_counter_table(&db).await;

    let conf = get_configuration(None).unwrap();
    let addr = conf.leptos_options.site_addr;
    let leptos_options = conf.leptos_options;
    // Generate the list of routes in your Leptos App
    let routes = generate_route_list(App);

    let app_state = AppState {
        leptos_options,
        routes: routes.clone(),
        db: db.clone(),
    };

    let app = Router::new()
        .route(
            "/api/{*fn_name}",
            get(server_fn_handler).post(server_fn_handler),
        )
        .leptos_routes_with_handler(routes, get(leptos_routes_handler))
        .layer(
            AuthSessionLayer::<User, i64, SessionSurrealPool<Any>, Surreal<Any>>::new(Some(db))
                .with_config(auth_config),
        )
        .layer(SessionLayer::new(session_store))
        .fallback(leptos_axum::file_and_error_handler::<AppState, _>(shell))
        .with_state(app_state);

    // run our app with hyper
    // `axum::Server` is a re-export of `hyper::Server`
    log!("listening on http://{}", &addr);
    let listener = tokio::net::TcpListener::bind(&addr).await.unwrap();
    axum::serve(listener, app.into_make_service())
        .await
        .unwrap();
}

#[cfg(not(feature = "ssr"))]
pub fn main() {
    // no client-side main function
    // unless we want this to work with e.g., Trunk for pure client-side testing
    // see lib.rs for hydration function instead
}
