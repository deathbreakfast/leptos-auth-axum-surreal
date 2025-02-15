use crate::auth::*;
use crate::counter::{get_count, BumpCount};
use crate::user::*;
use leptos::either::Either;
use leptos::prelude::*;
use leptos_meta::*;
use leptos_router::{components::*, *};

pub fn shell(options: LeptosOptions) -> impl IntoView {
    view! {
        <!DOCTYPE html>
        <html lang="en">
            <head>
                <meta charset="utf-8"/>
                <meta name="viewport" content="width=device-width, initial-scale=1"/>
                <AutoReload options=options.clone() />
                <HydrationScripts options/>
                <MetaTags/>
            </head>
            <body>
                <App/>
            </body>
        </html>
    }
}

#[component]
pub fn App() -> impl IntoView {
    // Provides context that manages stylesheets, titles, meta tags, etc.
    provide_meta_context();

    let login = ServerAction::<Login>::new();
    let logout = ServerAction::<Logout>::new();
    let signup = ServerAction::<Signup>::new();

    let user = Resource::new(
        move || {
            (
                login.version().get(),
                signup.version().get(),
                logout.version().get(),
            )
        },
        async move |_| current_user().await,
    );
    let login_value = Signal::derive(move || login.value().get().unwrap_or_else(|| Ok(())));
    let logout_value = Signal::derive(move || logout.value().get().unwrap_or_else(|| Ok(())));
    let signup_value = Signal::derive(move || signup.value().get().unwrap_or_else(|| Ok(())));
    let error_message = move |action: Signal<Result<(), ServerFnError>>| {
        let action_error = action.get().map_err(|e| e.to_string());
        if action_error.is_err() {
            Either::Left(view! {
                <p>{format!("{}", action_error.unwrap_err())}</p>
            })
        } else {
            Either::Right(view! {})
        }
    };

    view! {
        // injects a stylesheet into the document <head>
        // id=leptos means cargo-leptos will hot-reload this stylesheet
        <Stylesheet id="leptos" href="/pkg/leptos-auth-axum-surreal.css"/>

        // sets the document title
        <Title text="Welcome to Leptos"/>
        // content for this welcome page
        <Transition fallback=move || view! { <p>"Loading..."</p> }>
            {move || {
                // This is a hack to get the user to refetch. This should be done in a better way.
                // On page load, we pass the session id in the header, but we cant find the auth session.
                // Works on refresh.
                if user.get().is_some_and(|usr| usr.is_ok_and(|u| u.is_none()))
                { user.refetch(); }
            }}
            <ErrorBoundary fallback=|errors| {
                view! {
                    <p>"An error occurred: Error loading homepage"</p>
                    <ul>
                        {move || errors.get()
                            .into_iter()
                            .map(|(_, e)| {
                                view! {
                                    <li>{e.to_string()}</li>
                                }
                            })
                            .collect::<Vec<_>>()
                        }
                    </ul>
                }
            }>
                <Router>
                    <main>
                        <Routes fallback=|| "Page not found.".into_view()>
                            <Route path=StaticSegment("") view=move || view! { <HomePage user=user /> }/>
                            <Route path=path!("signup") view=move || view! { <Signup action=signup/> }/>
                            <Route path=path!("login") view=move || view! { <Login action=login/> }/>
                            <ProtectedRoute
                                path=path!("settings")
                                condition=move || {
                                    // This is always None on page load, but works on redirect. e.g. can't direclty go to /settings
                                    Some(user.get().is_some_and(|usr| usr.is_ok_and(|u| u.is_some())))
                                }
                                redirect_path=|| "/"
                                view=move || {
                                    view! {
                                        <h1>"Settings"</h1>
                                        <Logout action=logout/>
                                    }
                                }
                            />
                        </Routes>
                    </main>
                </Router>
            </ErrorBoundary>
            {move || error_message(login_value)}
            {move || error_message(signup_value)}
            {move || error_message(logout_value)}
        </Transition>
    }
}

/// Renders the home page of your application.
#[component]
fn HomePage(user: Resource<Result<Option<User>, ServerFnError>>) -> impl IntoView {
    let bump_count = ServerAction::<BumpCount>::new();

    let counter_resource = leptos::prelude::Resource::new(
        move || bump_count.version().get(),
        async move |_| get_count().await,
    );

    let on_click = move |_| {
        bump_count.dispatch(BumpCount { bump_count: 1 });
    };
    let bump_count_response =
        Signal::derive(move || bump_count.value().get().unwrap_or_else(|| Ok(())));
    let error_message = move || {
        if bump_count_response.get().is_err() {
            Either::Left(view! {
                <p>{format!("{:#?}", bump_count_response.get().unwrap_err().to_string())}</p>
            })
        } else {
            Either::Right(view! {})
        }
    };

    view! {
        <Transition fallback =move || view! { <p>"Loading..."</p> }>
            <ErrorBoundary fallback=|errors| {
                view! {
                    <p>"An error occurred: Click Me button did not load correctly"</p>
                    <ul>
                        {move || errors.get()
                            .into_iter()
                            .map(|(_, e)| {
                                view! {
                                    <li>{e.to_string()}</li>
                                }
                            })
                            .collect::<Vec<_>>()
                        }
                    </ul>
                }
            }>
                {move || user.get().map(|u| {
                    if u.as_ref().is_ok_and(|user| user.as_ref().is_some_and(|user| !user.anonymous)) {
                        Either::Left(view! {
                            <h1>Welcome to Leptos, {u.unwrap().unwrap().username}!</h1>
                            <A href="/settings">"Settings"</A>
                            <br/><br/>
                        })
                    } else {
                        Either::Right(view! {
                            <h1>"Welcome to Leptos!"</h1>
                            <br/>
                            <A href="/login">"Login"</A>
                            <br/>
                            <A href="/signup">"Sign Up"</A>
                            <br/><br/>
                        })
                    }
                })}
                {move || {
                    if let Some(counter) = counter_resource.get() {
                        Either::Left(view!{ <button on:click=on_click>"Click Me Count: " {counter.unwrap().count}</button>})
                    } else {
                        Either::Right(view!{ <button on:click=on_click>"Click Me Count: 0"</button> })
                    }
                }}
                <pre>{error_message}</pre>
            </ErrorBoundary>
        </Transition>
    }
}

#[component]
pub fn Login(action: ServerAction<Login>) -> impl IntoView {

    view! {
        <ErrorBoundary fallback=|error| {
            move || format!("An error occurred: {:#?}", error.get())
        }>
            <ActionForm action=action>
                <h1>"Log In"</h1>
                <label>
                    "User ID:"
                    <input
                        type="text"
                        placeholder="User ID"
                        maxlength="32"
                        name="username"
                        class="auth-input"
                    />
                </label>
                <br/>
                <label>
                    "Password:"
                    <input type="password" placeholder="Password" name="password" class="auth-input"/>
                </label>
                <br/>
                <label>
                    <input type="checkbox" name="remember" class="auth-input"/>
                    "Remember me?"
                </label>
                <br/>
                <button type="submit" class="button">
                    "Log In"
                </button>
            </ActionForm>
        </ErrorBoundary>
    }
}

#[component]
pub fn Signup(action: ServerAction<Signup>) -> impl IntoView {
    view! {
        <ActionForm action=action>
            <h1>"Sign Up"</h1>
            <label>
                "User ID:"
                <input
                    type="text"
                    placeholder="User ID"
                    maxlength="32"
                    name="username"
                    class="auth-input"
                />
            </label>
            <br/>
            <label>
                "Password:"
                <input type="password" placeholder="Password" name="password" class="auth-input"/>
            </label>
            <br/>
            <label>
                "Confirm Password:"
                <input
                    type="password"
                    placeholder="Password again"
                    name="password_confirmation"
                    class="auth-input"
                />
            </label>
            <br/>
            <label>
                "Remember me?" <input type="checkbox" name="remember" class="auth-input"/>
            </label>

            <br/>
            <button type="submit" class="button">
                "Sign Up"
            </button>
        </ActionForm>
    }
}

#[component]
pub fn Logout(action: ServerAction<Logout>) -> impl IntoView {
    view! {
        <div id="loginbox">
            <ActionForm action=action>
                <button type="submit" class="button">
                    "Log Out"
                </button>
            </ActionForm>
        </div>
    }
}
