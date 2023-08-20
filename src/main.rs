use actix_identity::{CookieIdentityPolicy, IdentityService};
use actix_web::{web, App, HttpRequest, HttpResponse, HttpServer, Responder};
use jsonwebtoken::{decode, encode, Header, Validation};
use serde::{Deserialize, Serialize};
use std::env;
use std::time::{Duration, SystemTime};

#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    sub: String,
    exp: usize,
}

async fn login() -> impl Responder {
    // For simplicity, we're hardcoding a username and password here.
    let username = "user";
    let password = "password";

    HttpResponse::Unauthorized()
        .header("WWW-Authenticate", "Basic realm=\"Restricted\"")
        .finish()
}

async fn restricted(req: HttpRequest) -> impl Responder {
    if let Some(identity) = req.identity() {
        let secret = env::var("JWT_SECRET_KEY").unwrap_or_else(|_| "secret".to_string());

        // Simulate JWT creation
        let claims = Claims {
            sub: identity,
            exp: SystemTime::now()
                .checked_add(Duration::from_secs(3600))
                .expect("valid time")
                .as_secs() as usize,
        };
        let token = encode(&Header::default(), &claims, secret.as_ref()).unwrap();

        HttpResponse::Ok().body(token)
    } else {
        HttpResponse::Unauthorized().finish()
    }
}

async fn validate_token(token: String) -> impl Responder {
    let secret = env::var("JWT_SECRET_KEY").unwrap_or_else(|_| "secret".to_string());

    let validation = Validation {
        ..Default::default()
    };

    match decode::<Claims>(&token, secret.as_ref(), &validation) {
        Ok(_) => HttpResponse::Ok(),
        Err(_) => HttpResponse::Unauthorized(),
    }
}

#[actix_rt::main]
async fn main() -> std::io::Result<()> {
    env::set_var("JWT_SECRET_KEY", "mysecretkey");

    HttpServer::new(|| {
        App::new()
            .wrap(IdentityService::new(
                CookieIdentityPolicy::new(env::var("JWT_SECRET_KEY").as_bytes())
                    .name("auth-cookie")
                    .secure(false),
            ))
            .route("/login", web::post().to(login))
            .route("/restricted", web::get().to(restricted))
            .route("/validate_token", web::post().to(web::to(validate_token)))
    })
    .bind("127.0.0.1:8080")?
    .run()
    .await
}
