use mimalloc::MiMalloc;

#[global_allocator]
static GLOBAL: MiMalloc = MiMalloc;

use arc_swap::ArcSwap;
use axum::{
    Json, Router,
    extract::{DefaultBodyLimit, Query, State, rejection::JsonRejection},
    http::{
        StatusCode, Uri,
        header::{CACHE_CONTROL, CONTENT_TYPE},
    },
    response::{IntoResponse, Response},
    routing::{get, post},
};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    collections::HashSet,
    fs::File,
    io::{BufRead, BufReader},
    net::{IpAddr, Ipv6Addr, SocketAddr},
    sync::Arc,
};

type DomainSet = HashSet<String, ahash::RandomState>;

// The blocklist is refreshed by deployment, not per request. Let the edge
// serve verification results for several hours and refresh them in background.
const VERIFY_CACHE_CONTROL: &str =
    "public, max-age=300, s-maxage=21600, stale-while-revalidate=604800";
const MAX_BATCH_DOMAINS: usize = 100;
const MAX_BATCH_BODY_BYTES: usize = 32 * 1024;
const BATCH_CACHE_CONTROL: &str = "no-store";

// --- Error Handling Standard ---

#[derive(Serialize)]
struct ApiError {
    message: String,
    error_code: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    extra: Option<Value>,
}

#[derive(Debug)]
enum AppError {
    Internal(String),
    BadRequest(String, String), // message, code
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, message, code, extra) = match self {
            AppError::Internal(msg) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                msg,
                "INTERNAL_SERVER_ERROR".to_string(),
                None,
            ),
            AppError::BadRequest(msg, code) => (StatusCode::BAD_REQUEST, msg, code, None),
        };

        let body = Json(ApiError {
            message,
            error_code: code,
            extra,
        });

        (status, body).into_response()
    }
}

// --- App Logic ---

pub fn load_domain_lines(path: &str) -> Result<HashSet<String>, String> {
    let file = File::open(path).map_err(|e| format!("Failed to open {path}: {e}"))?;
    let reader = BufReader::new(file);
    let mut domains = HashSet::new();
    for (index, line) in reader.lines().enumerate() {
        let line = line.map_err(|e| format!("Failed to read {path}: {e}"))?;
        let domain = line.trim().to_ascii_lowercase();
        if domain.is_empty() || domain.starts_with('#') {
            continue;
        }
        if !is_valid_domain(&domain) {
            return Err(format!("Invalid domain at {path}:{}: {domain}", index + 1));
        }
        domains.insert(domain);
    }
    Ok(domains)
}

fn ensure_no_protected_domains(
    blocklist: &HashSet<String>,
    protected: &HashSet<String>,
) -> Result<(), String> {
    let mut blocked_legitimate: Vec<_> = blocklist.intersection(protected).cloned().collect();
    blocked_legitimate.sort();
    if blocked_legitimate.is_empty() {
        Ok(())
    } else {
        Err(format!(
            "Blocklist contains legitimate domains: {}",
            blocked_legitimate.join(", ")
        ))
    }
}

fn load_runtime_domains(blocklist_path: &str, protected_path: &str) -> Result<DomainSet, AppError> {
    // Read the blocklist once and validate the exact set that will be served.
    let blocklist = load_domain_lines(blocklist_path).map_err(AppError::Internal)?;
    let protected = load_domain_lines(protected_path).map_err(AppError::Internal)?;
    ensure_no_protected_domains(&blocklist, &protected).map_err(AppError::Internal)?;
    Ok(blocklist.into_iter().collect())
}

pub fn is_valid_domain(domain: &str) -> bool {
    normalize_valid_domain(domain).is_some()
}

pub(crate) fn normalize_valid_domain(domain: &str) -> Option<std::borrow::Cow<'_, str>> {
    if domain.is_empty() || domain.len() > 253 {
        return None;
    }

    let mut label_len = 0;
    let mut dot_count = 0;
    let mut previous_was_hyphen = false;
    let mut has_uppercase = false;

    for byte in domain.bytes() {
        if byte == b'.' {
            if label_len == 0 || previous_was_hyphen {
                return None;
            }
            dot_count += 1;
            label_len = 0;
            previous_was_hyphen = false;
            continue;
        }

        let is_hyphen = byte == b'-';
        if !(byte.is_ascii_alphanumeric() || is_hyphen)
            || (label_len == 0 && is_hyphen)
            || label_len == 63
        {
            return None;
        }
        has_uppercase |= byte.is_ascii_uppercase();
        label_len += 1;
        previous_was_hyphen = is_hyphen;
    }

    if dot_count == 0 || label_len == 0 || previous_was_hyphen {
        return None;
    }

    if has_uppercase {
        Some(std::borrow::Cow::Owned(domain.to_ascii_lowercase()))
    } else {
        Some(std::borrow::Cow::Borrowed(domain))
    }
}

pub fn validate_blocklist(blocklist_path: &str, protected_path: &str) -> Result<(), String> {
    let blocklist = load_domain_lines(blocklist_path)?;
    let protected = load_domain_lines(protected_path)?;
    ensure_no_protected_domains(&blocklist, &protected)
}

#[derive(Clone)]
struct AppState {
    domains: Arc<ArcSwap<DomainSet>>,
}

fn create_app(state: AppState) -> Router {
    Router::new()
        .route("/v1/domains/verify", get(verify_handler))
        .route("/v1/domains/verify/compact", get(verify_compact_handler))
        .route(
            "/v1/domains/verify/batch",
            post(verify_batch_handler).layer(DefaultBodyLimit::max(MAX_BATCH_BODY_BYTES)),
        )
        .route(
            "/v1/domains/verify/batch/compact",
            post(verify_batch_compact_handler).layer(DefaultBodyLimit::max(MAX_BATCH_BODY_BYTES)),
        )
        .route("/health-check", get(health_check))
        .layer(
            tower_http::trace::TraceLayer::new_for_http()
                .make_span_with(|req: &axum::extract::Request<_>| {
                    let ip = req
                        .headers()
                        .get("x-forwarded-for")
                        .and_then(|header_value| header_value.to_str().ok())
                        .and_then(|header_value| {
                            header_value
                                .split(',')
                                .next()
                                .map(str::trim)
                                .map(str::to_string)
                        })
                        .or_else(|| {
                            req.extensions()
                                .get::<axum::extract::ConnectInfo<SocketAddr>>()
                                .map(|ci| ci.0.ip().to_string())
                        })
                        .unwrap_or_else(|| "unknown".into());

                    tracing::info_span!(
                        "http-request",
                        %ip,
                        method = %req.method(),
                        path = %req.uri().path(),
                        level = %tracing::Level::INFO
                    )
                })
                .on_response(
                    tower_http::trace::DefaultOnResponse::new().level(tracing::Level::INFO),
                ),
        )
        .with_state(state)
        .fallback(fallback_handler)
}

pub fn benchmark_app_with_domains(domains: impl IntoIterator<Item = String>) -> Router {
    let domains: DomainSet = domains.into_iter().collect();
    create_app(AppState {
        domains: Arc::new(ArcSwap::from_pointee(domains)),
    })
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    run().await
}

async fn run() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize tracing subscriber (logging)
    let _ = tracing_subscriber::fmt::try_init();

    // Resolve path: <current_dir>/assets/blocklist.txt
    let cwd = std::env::current_dir()?;
    let path_buffer = cwd.join("assets").join("blocklist.txt");
    let path = path_buffer
        .to_str()
        .expect("Path not defined properly")
        .to_string();
    let protected_path = cwd.join("assets").join("legitimate-domains.txt");
    let protected_path = protected_path
        .to_str()
        .expect("Protected-domain path not defined properly")
        .to_string();

    // Fail closed if the loaded list is malformed or contains protected domains.
    let initial_domains =
        load_runtime_domains(&path, &protected_path).map_err(|error| match error {
            AppError::Internal(message) => std::io::Error::other(message),
            AppError::BadRequest(message, _) => std::io::Error::other(message),
        })?;

    let state = AppState {
        domains: Arc::new(ArcSwap::from_pointee(initial_domains)),
    };

    let port = std::env::var("PORT").unwrap_or("9999".to_string());

    // Build application
    let _app = create_app(state);

    // Run server on localhost:<port>
    let _address = SocketAddr::from((IpAddr::from(Ipv6Addr::UNSPECIFIED), port.parse()?));

    // In test environment, we might not want to actually bind
    #[cfg(not(test))]
    {
        let listener = tokio::net::TcpListener::bind(_address).await?;
        tracing::info!("Starting server on {}", _address);
        axum::serve(
            listener,
            _app.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .await?;
    }

    Ok(())
}

async fn fallback_handler(uri: Uri) -> AppError {
    tracing::error!("No route for {}", uri);
    AppError::BadRequest(format!("No route for {}", uri), "ROUTE_NOT_FOUND".into())
}

async fn health_check() -> impl IntoResponse {
    (StatusCode::OK, Json(json!({ "status": "up" })))
}

#[derive(Debug, Deserialize)]
struct VerifyParams {
    domain: String,
}

#[derive(Serialize, Deserialize)]
struct VerifyResponse {
    domain: String,
    is_disposable: bool,
    source: std::borrow::Cow<'static, str>,
    checked_at: String,
}

fn verify_domain(
    state: &AppState,
    params: Result<Query<VerifyParams>, axum::extract::rejection::QueryRejection>,
) -> Result<(String, bool), AppError> {
    let Query(params) = params.map_err(|e| {
        AppError::BadRequest(
            format!("Invalid query parameters: {}", e),
            "INVALID_QUERY_PARAMS".into(),
        )
    })?;

    let domain = params.domain;

    let search_domain = normalize_valid_domain(&domain).ok_or_else(|| {
        AppError::BadRequest(
            "The domain parameter must be a valid hostname".into(),
            "INVALID_DOMAIN".into(),
        )
    })?;

    // Use ArcSwap load to get a handle to the current set
    let domains = state.domains.load();
    let is_disposable = domains.contains(search_domain.as_ref());
    Ok((domain, is_disposable))
}

async fn verify_handler(
    State(state): State<AppState>,
    params: Result<Query<VerifyParams>, axum::extract::rejection::QueryRejection>,
) -> Result<impl IntoResponse, AppError> {
    let (domain, is_disposable) = verify_domain(&state, params)?;
    let now = Utc::now().to_rfc3339();

    Ok((
        StatusCode::OK,
        [(CACHE_CONTROL, VERIFY_CACHE_CONTROL)],
        Json(VerifyResponse {
            domain,
            is_disposable,
            source: std::borrow::Cow::Borrowed("assets/blocklist.txt"),
            checked_at: now,
        }),
    ))
}

async fn verify_compact_handler(
    State(state): State<AppState>,
    params: Result<Query<VerifyParams>, axum::extract::rejection::QueryRejection>,
) -> Result<impl IntoResponse, AppError> {
    let (_, is_disposable) = verify_domain(&state, params)?;
    let result = if is_disposable { "1" } else { "0" };
    Ok(([(CACHE_CONTROL, VERIFY_CACHE_CONTROL)], result))
}

#[derive(Deserialize)]
struct BatchVerifyRequest {
    domains: Vec<String>,
}

#[derive(Serialize)]
struct BatchVerifyResponse {
    results: Vec<bool>,
}

fn verify_batch(
    state: &AppState,
    payload: Result<Json<BatchVerifyRequest>, JsonRejection>,
) -> Result<Vec<bool>, (StatusCode, Json<ApiError>)> {
    let Json(payload) = payload.map_err(|error| {
        (
            error.status(),
            Json(ApiError {
                message: "Expected a JSON object with a domains array within the body limit".into(),
                error_code: "INVALID_BATCH_BODY".into(),
                extra: None,
            }),
        )
    })?;

    if !(1..=MAX_BATCH_DOMAINS).contains(&payload.domains.len()) {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ApiError {
                message: format!("The domains array must contain 1 to {MAX_BATCH_DOMAINS} entries"),
                error_code: "INVALID_BATCH_SIZE".into(),
                extra: None,
            }),
        ));
    }

    let domains = state.domains.load();
    let mut results = Vec::with_capacity(payload.domains.len());
    for (index, domain) in payload.domains.iter().enumerate() {
        let normalized = normalize_valid_domain(domain).ok_or_else(|| {
            (
                StatusCode::BAD_REQUEST,
                Json(ApiError {
                    message: format!("Domain at index {index} must be a valid hostname"),
                    error_code: "INVALID_DOMAIN".into(),
                    extra: None,
                }),
            )
        })?;
        results.push(domains.contains(normalized.as_ref()));
    }
    Ok(results)
}

async fn verify_batch_handler(
    State(state): State<AppState>,
    payload: Result<Json<BatchVerifyRequest>, JsonRejection>,
) -> Response {
    let response = match verify_batch(&state, payload) {
        Ok(results) => Json(BatchVerifyResponse { results }).into_response(),
        Err(error) => error.into_response(),
    };
    ([(CACHE_CONTROL, BATCH_CACHE_CONTROL)], response).into_response()
}

async fn verify_batch_compact_handler(
    State(state): State<AppState>,
    payload: Result<Json<BatchVerifyRequest>, JsonRejection>,
) -> Response {
    let response = match verify_batch(&state, payload) {
        Ok(results) => {
            let mut packed = vec![0u8; results.len().div_ceil(8)];
            for (index, is_disposable) in results.into_iter().enumerate() {
                if is_disposable {
                    packed[index / 8] |= 1 << (index % 8);
                }
            }
            ([(CONTENT_TYPE, "application/octet-stream")], packed).into_response()
        }
        Err(error) => error.into_response(),
    };
    ([(CACHE_CONTROL, BATCH_CACHE_CONTROL)], response).into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::Request;
    use http_body_util::BodyExt;
    use serde_json::Value;
    use std::io::Write;
    use tempfile::NamedTempFile;
    use tower::ServiceExt;

    #[test]
    fn test_load_domains_from_file() {
        let mut file = NamedTempFile::new().unwrap();
        writeln!(file, "example.com").unwrap();
        writeln!(file, "  SPAM.ORG  ").unwrap();
        writeln!(file, "# comment").unwrap();
        writeln!(file).unwrap();
        writeln!(file, "disposable.net").unwrap();

        let domains = load_domain_lines(file.path().to_str().unwrap()).unwrap();

        assert_eq!(domains.len(), 3);
        assert!(domains.contains("example.com"));
        assert!(domains.contains("spam.org"));
        assert!(domains.contains("disposable.net"));
        assert!(!domains.contains("# comment"));
    }

    #[test]
    fn blocklist_validator_rejects_protected_domains_and_malformed_lines() {
        let blocklist = NamedTempFile::new().unwrap();
        let protected = NamedTempFile::new().unwrap();
        std::fs::write(blocklist.path(), "mailinator.com\ngmail.com\n").unwrap();
        std::fs::write(protected.path(), "gmail.com\n").unwrap();
        assert!(
            validate_blocklist(
                blocklist.path().to_str().unwrap(),
                protected.path().to_str().unwrap()
            )
            .unwrap_err()
            .contains("gmail.com")
        );

        std::fs::write(blocklist.path(), "mailinator.com\nnot a domain\n").unwrap();
        assert!(
            validate_blocklist(
                blocklist.path().to_str().unwrap(),
                protected.path().to_str().unwrap()
            )
            .unwrap_err()
            .contains("Invalid domain")
        );
    }

    #[test]
    fn hostname_validation_rejects_urls_emails_and_invalid_labels() {
        for invalid in [
            "https://example.com",
            "user@example.com",
            "example.com/path",
            "-bad.example",
            "bad-.example",
            "example..com",
            "localhost",
        ] {
            assert!(
                !is_valid_domain(invalid),
                "accepted invalid hostname: {invalid}"
            );
        }
        for valid in ["example.com", "sub.example.co.uk", "xn--bcher-kva.example"] {
            assert!(is_valid_domain(valid), "rejected valid hostname: {valid}");
        }
        assert_eq!(
            normalize_valid_domain("Mail.Example.COM").unwrap(),
            "mail.example.com"
        );
        assert!(matches!(
            normalize_valid_domain("example.com"),
            Some(std::borrow::Cow::Borrowed(_))
        ));
    }

    #[test]
    fn blocklist_loader_rejects_malformed_entries() {
        let blocklist = NamedTempFile::new().unwrap();
        std::fs::write(blocklist.path(), "valid.example\nnot a domain\n").unwrap();
        assert!(load_domain_lines(blocklist.path().to_str().unwrap()).is_err());
    }

    #[tokio::test]
    async fn compact_verify_returns_one_byte_and_keeps_json_errors() {
        let domains = DomainSet::from_iter(["disposable.example".to_owned()]);
        let app = create_app(AppState {
            domains: Arc::new(ArcSwap::from_pointee(domains)),
        });
        for (query, expected) in [
            ("?domain=Disposable.Example", "1"),
            ("?domain=other.example", "0"),
        ] {
            let response = app
                .clone()
                .oneshot(
                    Request::builder()
                        .uri(format!("/v1/domains/verify/compact{query}"))
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK);
            assert_eq!(
                response.headers()["content-type"],
                "text/plain; charset=utf-8"
            );
            assert_eq!(response.headers()[CACHE_CONTROL], VERIFY_CACHE_CONTROL);
            assert_eq!(
                response.into_body().collect().await.unwrap().to_bytes(),
                expected
            );
        }
        for (query, code) in [
            ("", "INVALID_QUERY_PARAMS"),
            ("?domain=not%20valid", "INVALID_DOMAIN"),
        ] {
            let response = app
                .clone()
                .oneshot(
                    Request::builder()
                        .uri(format!("/v1/domains/verify/compact{query}"))
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::BAD_REQUEST);
            assert_eq!(response.headers()["content-type"], "application/json");
            let body = response.into_body().collect().await.unwrap().to_bytes();
            let error: Value = serde_json::from_slice(&body).unwrap();
            assert_eq!(error["error_code"], code);
        }
    }

    #[tokio::test]
    async fn verify_endpoint_rejects_invalid_domain_values() {
        let state = AppState {
            domains: Arc::new(ArcSwap::from_pointee(DomainSet::default())),
        };
        let response = create_app(state)
            .oneshot(
                Request::builder()
                    .uri("/v1/domains/verify?domain=https%3A%2F%2Fexample.com")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let error: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(error["error_code"], "INVALID_DOMAIN");
    }

    #[test]
    fn canonical_blocklist_does_not_contain_protected_domains() {
        validate_blocklist("assets/blocklist.txt", "assets/legitimate-domains.txt").unwrap();
    }

    #[test]
    fn runtime_loader_fails_closed_for_protected_domains() {
        let blocklist = NamedTempFile::new().unwrap();
        let protected = NamedTempFile::new().unwrap();
        std::fs::write(blocklist.path(), "disposable.example\ngmail.com\n").unwrap();
        std::fs::write(protected.path(), "gmail.com\n").unwrap();

        let error = load_runtime_domains(
            blocklist.path().to_str().unwrap(),
            protected.path().to_str().unwrap(),
        )
        .unwrap_err();

        assert!(format!("{error:?}").contains("gmail.com"));
    }

    #[test]
    fn validate_blocklist_uses_explicit_candidate_path() {
        let candidate = NamedTempFile::new().unwrap();
        let protected = NamedTempFile::new().unwrap();
        std::fs::write(candidate.path(), "mailinator.com\n").unwrap();
        std::fs::write(protected.path(), "gmail.com\n").unwrap();
        validate_blocklist(
            candidate.path().to_str().unwrap(),
            protected.path().to_str().unwrap(),
        )
        .unwrap();
    }

    #[tokio::test]
    async fn test_verify_handler_logic() {
        let mut domains = DomainSet::default();
        domains.insert("disposable.com".to_string());

        let state = AppState {
            domains: Arc::new(ArcSwap::from_pointee(domains)),
        };

        // Test with disposable domain
        let params = Query(VerifyParams {
            domain: "DISPOSABLE.COM".to_string(),
        });
        let response = verify_handler(State(state.clone()), Ok(params))
            .await
            .unwrap()
            .into_response();
        assert_eq!(response.status(), StatusCode::OK);

        // Test with safe domain
        let params = Query(VerifyParams {
            domain: "google.com".to_string(),
        });
        let response = verify_handler(State(state), Ok(params))
            .await
            .unwrap()
            .into_response();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_health_check_integration() {
        let state = AppState {
            domains: Arc::new(ArcSwap::from_pointee(DomainSet::default())),
        };
        let app = create_app(state);

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/health-check")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = response.into_body().collect().await.unwrap().to_bytes();
        let body: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(body["status"], "up");
    }

    #[tokio::test]
    async fn test_verify_integration() {
        let mut domains = DomainSet::default();
        domains.insert("trashmail.com".to_string());

        let state = AppState {
            domains: Arc::new(ArcSwap::from_pointee(domains)),
        };
        let app = create_app(state);

        // Test disposable domain
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/v1/domains/verify?domain=trashmail.com")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers().get("cache-control").unwrap(),
            "public, max-age=300, s-maxage=21600, stale-while-revalidate=604800"
        );
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let resp: VerifyResponse = serde_json::from_slice(&body).unwrap();
        assert!(resp.is_disposable);
        assert_eq!(resp.domain, "trashmail.com");

        // Test with invalid query param (missing domain) - should return 400 with our standard error structure
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/v1/domains/verify")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let err: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(err["error_code"], "INVALID_QUERY_PARAMS");
    }

    #[tokio::test]
    async fn test_fallback_handler() {
        let state = AppState {
            domains: Arc::new(ArcSwap::from_pointee(DomainSet::default())),
        };
        let app = create_app(state);

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/not-found")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST); // Fallback returns 400 for bad routes in our code
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let body: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(body["error_code"], "ROUTE_NOT_FOUND");
    }

    #[tokio::test]
    async fn test_run_smoke() {
        std::fs::create_dir_all("assets").unwrap();
        if !std::path::Path::new("assets/blocklist.txt").exists() {
            std::fs::write("assets/blocklist.txt", "example.com").unwrap();
        }
        let result = run().await;
        assert!(result.is_ok());
    }

    async fn post_batch(app: &Router, path: &str, body: String, content_type: &str) -> Response {
        app.clone()
            .oneshot(
                Request::post(path)
                    .header(CONTENT_TYPE, content_type)
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn batch_formats_preserve_order_duplicates_and_zero_padding() {
        let app = benchmark_app_with_domains(["disposable.example".to_owned()]);
        let domains: Vec<_> = (0..MAX_BATCH_DOMAINS)
            .map(|index| {
                if [0, 7, 8, 99].contains(&index) {
                    "Disposable.Example"
                } else {
                    "other.example"
                }
            })
            .collect();
        let payload = json!({ "domains": domains }).to_string();
        let expected: Vec<_> = (0..MAX_BATCH_DOMAINS)
            .map(|index| [0, 7, 8, 99].contains(&index))
            .collect();
        for (suffix, content_type) in [
            ("", "application/json"),
            ("/compact", "application/octet-stream"),
        ] {
            let response = post_batch(
                &app,
                &format!("/v1/domains/verify/batch{suffix}"),
                payload.clone(),
                "application/json",
            )
            .await;
            assert_eq!(response.status(), StatusCode::OK);
            assert_eq!(response.headers()[CONTENT_TYPE], content_type);
            assert_eq!(response.headers()[CACHE_CONTROL], "no-store");
            let body = response.into_body().collect().await.unwrap().to_bytes();
            if suffix.is_empty() {
                assert_eq!(
                    serde_json::from_slice::<Value>(&body).unwrap(),
                    json!({ "results": expected })
                );
            } else {
                assert_eq!(body.as_ref(), &[0x81, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 8]);
            }
        }
    }

    #[tokio::test]
    async fn batch_formats_reject_invalid_requests_without_partial_results() {
        let app = benchmark_app_with_domains(["disposable.example".to_owned()]);
        for path in [
            "/v1/domains/verify/batch",
            "/v1/domains/verify/batch/compact",
        ] {
            for (body, content_type, status, error_code) in [
                (
                    json!({"domains": []}).to_string(),
                    "application/json",
                    StatusCode::BAD_REQUEST,
                    "INVALID_BATCH_SIZE",
                ),
                (
                    json!({"domains": vec!["some.example"; MAX_BATCH_DOMAINS + 1]}).to_string(),
                    "application/json",
                    StatusCode::BAD_REQUEST,
                    "INVALID_BATCH_SIZE",
                ),
                (
                    json!({"domains": ["disposable.example", "a@example.com"]}).to_string(),
                    "application/json",
                    StatusCode::BAD_REQUEST,
                    "INVALID_DOMAIN",
                ),
                (
                    "{".to_owned(),
                    "application/json",
                    StatusCode::BAD_REQUEST,
                    "INVALID_BATCH_BODY",
                ),
                (
                    json!({"domains": [42]}).to_string(),
                    "application/json",
                    StatusCode::UNPROCESSABLE_ENTITY,
                    "INVALID_BATCH_BODY",
                ),
                (
                    json!({"domains": ["some.example"]}).to_string(),
                    "text/plain",
                    StatusCode::UNSUPPORTED_MEDIA_TYPE,
                    "INVALID_BATCH_BODY",
                ),
                (
                    " ".repeat(MAX_BATCH_BODY_BYTES + 1),
                    "application/json",
                    StatusCode::PAYLOAD_TOO_LARGE,
                    "INVALID_BATCH_BODY",
                ),
            ] {
                let response = post_batch(&app, path, body, content_type).await;
                assert_eq!(response.status(), status);
                assert_eq!(response.headers()[CONTENT_TYPE], "application/json");
                assert_eq!(response.headers()[CACHE_CONTROL], "no-store");
                let body = response.into_body().collect().await.unwrap().to_bytes();
                let error: Value = serde_json::from_slice(&body).unwrap();
                assert_eq!(error["error_code"], error_code);
                assert!(error.get("results").is_none());
            }
        }
    }
}
