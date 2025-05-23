use std::sync::Arc;

use axum::Extension;
use rand::{distr::Alphanumeric, rng, Rng};
use serde::{Deserialize, Serialize};

#[derive(Deserialize, Serialize)]
pub struct DocumentRequest {
    content: String,
    parameters: String,
    output_filename: String,
}

/// Application state.
/// It holds the authentifaction token provided to login.
pub struct State {
    pub token: String,
}

impl Default for State {
    fn default() -> Self {
        let token = Self::generate_random_token();
        println!("State generated token {token}");
        Self { token }
    }
}

impl State {
    fn generate_random_token() -> String {
        let mut rng = rng();
        (0..32).map(|_| rng.sample(Alphanumeric) as char).collect()
    }
}

pub mod route {
    use super::*;
    use std::fs::write;
    use std::process::{Command, Output, Stdio};

    use axum::{
        body::{Bytes, Full},
        extract::Json,
        http::{Response, StatusCode},
        response::Html,
        response::IntoResponse,
    };
    use tracing::info;

    const INPUT_FILE: &str = "input.md";

    pub async fn login<B>(state: Extension<Arc<State>>) -> Response<Full<B>>
    where
        B: Send + 'static + std::convert::From<&'static str> + bytes::Buf,
    {
        Response::builder()
            .header(
                "Set-Cookie",
                format!(
                    "authToken={}; Path=/; HttpOnly; Secure; SameSite=Strict",
                    state.token
                ),
            )
            .body(Full::from(include_str!("../static/login.html")))
            .expect("Couldn't serve login")
    }

    pub async fn index() -> Html<&'static str> {
        Html(include_str!("../static/index.html"))
    }

    pub async fn style_css() -> impl IntoResponse {
        Response::builder()
            .header("Content-Type", "text/css")
            .body(Full::from(include_str!("../static/style.css")))
            .expect("Couldn't server style.css")
    }

    /// Write the content to a temporary input file
    fn temp_save_payload(content: &str) {
        write(INPUT_FILE, content).expect("Failed to write input file");
        let input_content = std::fs::read_to_string(INPUT_FILE).expect("Couldn't read input file");
        info!("Input file {input_content}");
    }

    /// Construct the pandoc command
    fn build_pandoc_command(parameters: &str, output_file: &str) -> Command {
        let mut command = Command::new("pandoc");

        command
            .arg(INPUT_FILE)
            .args(parameters.split_whitespace())
            .arg("-o")
            .arg(output_file)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());

        let args: Vec<_> = command.get_args().collect();
        info!(
            "Command {command} - args {args:?}",
            command = command
                .get_program()
                .to_str()
                .expect("Couldn't read program name"),
        );
        command
    }

    fn run_pandoc(mut command: Command) -> Output {
        command
            .spawn()
            .expect("Failed to spawn pandoc process")
            .wait_with_output()
            .expect("Pandoc command failed")
    }

    /// Clean up the temporary input file
    fn clean_temp_file() {
        std::fs::remove_file(INPUT_FILE).expect("Failed to remove input file");
    }

    fn build_successful_response(output_file: &str) -> Response<Full<Bytes>> {
        // Read the generated output file
        let generated_content = std::fs::read(output_file).expect("Failed to read output file");

        // Clean up the output file
        std::fs::remove_file(output_file).expect("Failed to remove output file");

        Response::builder()
            .status(StatusCode::OK)
            .header("Content-Type", "application/octet-stream")
            .body(Full::from(generated_content))
            .expect("Couldn't build successful body")
    }

    fn build_failure_response(output: &Output) -> Response<Full<Bytes>> {
        let error_message = String::from_utf8_lossy(&output.stderr);
        Response::builder()
            .status(StatusCode::INTERNAL_SERVER_ERROR)
            .body(Full::from(error_message.into_owned().into_bytes()))
            .expect("Couldn't build failure body")
    }

    pub async fn handle_document(Json(payload): Json<DocumentRequest>) -> impl IntoResponse {
        let output_file = &payload.output_filename;

        temp_save_payload(&payload.content);
        let command = build_pandoc_command(&payload.parameters, output_file);
        let output = run_pandoc(command);
        clean_temp_file();

        if output.status.success() {
            build_successful_response(output_file)
        } else {
            build_failure_response(&output)
        }
    }
}

pub mod logger {
    use std::fs::{File, OpenOptions};

    use tracing::{level_filters::LevelFilter, Level};
    use tracing_subscriber::{
        fmt::format::{DefaultFields, Format},
        FmtSubscriber,
    };

    const LOG_FILE: &str = "src/paas.log";

    fn erase_big_log() {
        let log_file_path = std::path::Path::new(LOG_FILE);
        if log_file_path.exists() && log_file_path.metadata().expect("").len() > 1024 * 1024 {
            std::fs::remove_file(log_file_path).expect("Couldn't delete log file");
            println!("Deleted logfile which was too big");
        }
    }

    fn open_log() -> File {
        OpenOptions::new()
            .append(true)
            .open(LOG_FILE)
            .unwrap_or_else(|_| File::create(LOG_FILE).expect("Couldn't open nor create log file"))
    }

    fn setup_subscriber(file: File) -> FmtSubscriber<DefaultFields, Format, LevelFilter, File> {
        FmtSubscriber::builder()
            .with_max_level(Level::INFO)
            .with_ansi(false)
            .with_writer(file)
            .finish()
    }

    /// Initialize logging
    pub fn setup_logger() {
        erase_big_log();
        let file = open_log();
        let subscriber = setup_subscriber(file);
        tracing::subscriber::set_global_default(subscriber)
            .expect("setting default subscriber failed");
    }
}

pub mod server {
    use super::*;
    use std::env;

    use axum::{
        http::{Request, StatusCode},
        middleware::{self, Next},
        response::Response,
        routing::{get, post},
        Router,
    };

    async fn check_auth<B>(
        state: Extension<Arc<State>>,
        request: Request<B>,
        next: Next<B>,
    ) -> Result<Response, StatusCode>
    where
        B: Send + 'static,
    {
        let cookies = request
            .headers()
            .get("Cookie")
            .and_then(|header| header.to_str().ok())
            .unwrap_or("");

        let auth_token = cookies
            .split(';')
            .find(|cookie| cookie.trim().starts_with("authToken="))
            .and_then(|cookie| cookie.split('=').nth(1));

        println!(
            "auth_token {auth_token:?} - state.token {st:?}",
            st = Some(&state.token)
        );
        if auth_token == Some(&state.token) {
            Ok(next.run(request).await)
        } else {
            Err(StatusCode::UNAUTHORIZED)
        }
    }

    fn build_app(state: Arc<State>) -> Router {
        let protected_routes = Router::new()
            .route("/", get(route::index))
            .route("/style.css", get(route::style_css))
            .route("/document", post(route::handle_document))
            .route_layer(middleware::from_fn(check_auth));

        Router::new()
            .route("/login", get(route::login))
            .merge(protected_routes)
            .layer(Extension(state))
    }

    fn format_addr() -> String {
        let port = env::var("PORT").unwrap_or_else(|_| "3000".to_string());
        println!("Starting PAAS. Listening on port {port}");
        format!("0.0.0.0:{}", port)
    }

    async fn build_server(app: Router, addr: String) {
        axum::Server::bind(&addr.parse().unwrap())
            .serve(app.into_make_service())
            .await
            .expect("Couldn't build server");
    }

    pub async fn serve(state: Arc<State>) {
        let app = build_app(state);
        let addr = format_addr();
        build_server(app, addr).await
    }
}

#[tokio::main]
async fn main() {
    logger::setup_logger();
    let state = Arc::new(State::default());
    server::serve(state).await;
}
