use serde::{Deserialize, Serialize};

#[derive(Deserialize, Serialize)]
pub struct DocumentRequest {
    content: String,
    parameters: String,
    output_filename: String,
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
            .expect("Pandoc failed")
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
    use std::fs::OpenOptions;

    use tracing::Level;
    use tracing_subscriber::FmtSubscriber;

    const LOG_FILE: &str = "src/paas.log";
    /// Initialize logging
    pub fn setup_logger() {
        let file = OpenOptions::new()
            .append(true)
            .open(LOG_FILE)
            .expect("Couldn't create log file");
        let subscriber = FmtSubscriber::builder()
            .with_max_level(Level::INFO)
            .with_ansi(false)
            .with_writer(file)
            // .with_target(false)
            .finish();
        tracing::subscriber::set_global_default(subscriber)
            .expect("setting default subscriber failed");
    }
}

pub mod server {
    use super::*;
    use std::env;

    use axum::{
        routing::{get, post},
        Router,
    };

    fn build_app() -> Router {
        Router::new()
            .route("/", get(route::index))
            .route("/style.css", get(route::style_css))
            .route("/document", post(route::handle_document))
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

    pub async fn serve() {
        let app = build_app();
        let addr = format_addr();
        build_server(app, addr).await
    }
}

#[tokio::main]
async fn main() {
    logger::setup_logger();
    server::serve().await;
}
