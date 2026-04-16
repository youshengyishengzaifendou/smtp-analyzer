//! 本地 HTTP 服务

use std::collections::HashMap;
use std::fs::{self, File};
use std::io::{Read, Write};
use std::net::{IpAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use log::{error, info, warn};
use serde::{Deserialize, Serialize};

use crate::app::{analyze_capture, normalize_ports, parse_ports, AnalysisRequest};
use crate::error::{AnalyzerError, Result};

const MAX_HEADER_SIZE: usize = 64 * 1024;
const MAX_JSON_BODY_SIZE: usize = 8 * 1024 * 1024;
const MAX_UPLOAD_BODY_SIZE: usize = 1024 * 1024 * 1024;
const ALLOWED_CAPTURE_EXTENSIONS: [&str; 4] = ["pcap", "pcapng", "cap", "dump"];
const CONNECTION_IO_TIMEOUT: Duration = Duration::from_secs(30);
const MIN_WORKER_THREADS: usize = 4;
const MAX_WORKER_THREADS: usize = 16;
const ALLOW_HEADERS: [(&str, &str); 1] = [("Allow", "GET, POST, OPTIONS")];
const INDEX_HTML: &str = include_str!("../web/index.html");
const APP_JS: &str = include_str!("../web/app.js");
const STYLES_CSS: &str = include_str!("../web/styles.css");

static UPLOAD_COUNTER: AtomicU64 = AtomicU64::new(0);

#[derive(Debug)]
struct HttpRequestHead {
    method: String,
    path: String,
    headers: HashMap<String, String>,
    body_prefix: Vec<u8>,
}

#[derive(Debug, Deserialize)]
struct AnalyzeHttpRequest {
    file: String,
    ports: Option<Vec<u16>>,
    ignore_vlan: Option<bool>,
}

#[derive(Debug, Serialize)]
struct ErrorPayload<'a> {
    error: &'a str,
}

#[derive(Debug, Serialize)]
struct HealthPayload<'a> {
    status: &'a str,
}

#[derive(Debug)]
struct HttpError {
    status: &'static str,
    message: String,
    headers: &'static [(&'static str, &'static str)],
}

type HttpResult<T> = std::result::Result<T, HttpError>;

impl HttpError {
    fn new(status: &'static str, message: impl Into<String>) -> Self {
        Self {
            status,
            message: message.into(),
            headers: &[],
        }
    }

    fn with_headers(
        status: &'static str,
        message: impl Into<String>,
        headers: &'static [(&'static str, &'static str)],
    ) -> Self {
        Self {
            status,
            message: message.into(),
            headers,
        }
    }

    fn bad_request(message: impl Into<String>) -> Self {
        Self::new("400 Bad Request", message)
    }

    fn forbidden(message: impl Into<String>) -> Self {
        Self::new("403 Forbidden", message)
    }

    fn not_found(message: impl Into<String>) -> Self {
        Self::new("404 Not Found", message)
    }

    fn method_not_allowed(message: impl Into<String>) -> Self {
        Self::with_headers("405 Method Not Allowed", message, &ALLOW_HEADERS)
    }

    fn request_timeout(message: impl Into<String>) -> Self {
        Self::new("408 Request Timeout", message)
    }

    fn length_required(message: impl Into<String>) -> Self {
        Self::new("411 Length Required", message)
    }

    fn payload_too_large(message: impl Into<String>) -> Self {
        Self::new("413 Payload Too Large", message)
    }

    fn unsupported_media_type(message: impl Into<String>) -> Self {
        Self::new("415 Unsupported Media Type", message)
    }

    fn unprocessable_content(message: impl Into<String>) -> Self {
        Self::new("422 Unprocessable Content", message)
    }

    fn header_fields_too_large(message: impl Into<String>) -> Self {
        Self::new("431 Request Header Fields Too Large", message)
    }

    fn internal_server_error(message: impl Into<String>) -> Self {
        Self::new("500 Internal Server Error", message)
    }

    fn from_read_error(context: &str, err: std::io::Error) -> Self {
        match err.kind() {
            std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock => {
                Self::request_timeout(format!("{context}: request timed out"))
            }
            _ => Self::internal_server_error(format!("{context}: {}", err)),
        }
    }
}

pub fn serve(host: &str, port: u16) -> Result<()> {
    validate_bind_host(host)?;

    let bind_addr = format!("{host}:{port}");
    let listener = TcpListener::bind(&bind_addr)?;
    let worker_count = determine_worker_count();
    let (sender, receiver) = mpsc::channel::<TcpStream>();
    let shared_receiver = Arc::new(Mutex::new(receiver));
    let started_workers = spawn_worker_threads(Arc::clone(&shared_receiver), worker_count);

    if started_workers == 0 {
        return Err(std::io::Error::other("failed to start HTTP worker threads").into());
    }

    info!("HTTP 服务已启动: http://{}", bind_addr);
    info!("健康检查: http://{}/health", bind_addr);
    info!("上传分析接口: POST http://{}/analyze-upload", bind_addr);
    info!("HTTP 工作线程数: {}", started_workers);

    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                if let Err(err) = configure_stream(&stream) {
                    warn!("配置 HTTP 连接失败: {}", err);
                    continue;
                }

                if let Err(err) = sender.send(stream) {
                    error!("分发 HTTP 连接到工作线程失败: {}", err);
                    break;
                }
            }
            Err(err) => {
                error!("接受连接失败: {}", err);
            }
        }
    }

    Ok(())
}

fn determine_worker_count() -> usize {
    std::thread::available_parallelism()
        .map(|parallelism| {
            parallelism
                .get()
                .clamp(MIN_WORKER_THREADS, MAX_WORKER_THREADS)
        })
        .unwrap_or(MIN_WORKER_THREADS)
}

fn spawn_worker_threads(
    receiver: Arc<Mutex<mpsc::Receiver<TcpStream>>>,
    worker_count: usize,
) -> usize {
    let mut started = 0;

    for index in 0..worker_count {
        let receiver = Arc::clone(&receiver);
        let thread_name = format!("smtp-analyzer-http-{index}");

        match thread::Builder::new()
            .name(thread_name)
            .spawn(move || worker_loop(receiver))
        {
            Ok(_) => started += 1,
            Err(err) => warn!("启动 HTTP 工作线程失败: {}", err),
        }
    }

    started
}

fn worker_loop(receiver: Arc<Mutex<mpsc::Receiver<TcpStream>>>) {
    loop {
        let stream_result = match receiver.lock() {
            Ok(guard) => guard.recv(),
            Err(poisoned) => {
                error!("HTTP 工作队列锁已损坏，继续处理剩余连接");
                poisoned.into_inner().recv()
            }
        };

        let mut stream = match stream_result {
            Ok(stream) => stream,
            Err(_) => break,
        };

        if let Err(err) = handle_connection(&mut stream) {
            log_http_error(&err);
            if let Err(write_err) = write_error_response(&mut stream, &err) {
                warn!("回写 HTTP 错误响应失败: {}", write_err);
            }
        }
    }
}

fn configure_stream(stream: &TcpStream) -> std::io::Result<()> {
    stream.set_read_timeout(Some(CONNECTION_IO_TIMEOUT))?;
    stream.set_write_timeout(Some(CONNECTION_IO_TIMEOUT))?;
    stream.set_nodelay(true)
}

fn log_http_error(err: &HttpError) {
    if err.status.starts_with('5') {
        error!("HTTP 请求失败 [{}]: {}", err.status, err.message);
    } else {
        warn!("HTTP 请求失败 [{}]: {}", err.status, err.message);
    }
}

fn handle_connection(stream: &mut TcpStream) -> HttpResult<()> {
    let request = read_request_head(stream)?;

    if request.method == "OPTIONS" {
        return write_response_with_headers(
            stream,
            "204 No Content",
            "text/plain; charset=utf-8",
            b"",
            &ALLOW_HEADERS,
        )
        .map_err(|err| HttpError::internal_server_error(err.to_string()));
    }

    match request.path.as_str() {
        "/" => {
            require_method(&request, "GET")?;
            write_response(
                stream,
                "200 OK",
                "text/html; charset=utf-8",
                INDEX_HTML.as_bytes(),
            )
            .map_err(|err| HttpError::internal_server_error(err.to_string()))
        }
        "/app.js" => {
            require_method(&request, "GET")?;
            write_response(
                stream,
                "200 OK",
                "application/javascript; charset=utf-8",
                APP_JS.as_bytes(),
            )
            .map_err(|err| HttpError::internal_server_error(err.to_string()))
        }
        "/styles.css" => {
            require_method(&request, "GET")?;
            write_response(
                stream,
                "200 OK",
                "text/css; charset=utf-8",
                STYLES_CSS.as_bytes(),
            )
            .map_err(|err| HttpError::internal_server_error(err.to_string()))
        }
        "/health" => {
            require_method(&request, "GET")?;
            let body = serde_json::to_vec(&HealthPayload { status: "ok" })
                .map_err(|err| HttpError::internal_server_error(err.to_string()))?;
            write_response(stream, "200 OK", "application/json; charset=utf-8", &body)
                .map_err(|err| HttpError::internal_server_error(err.to_string()))
        }
        "/analyze" => {
            require_method(&request, "POST")?;
            handle_analyze(stream, request)
        }
        "/analyze-upload" => {
            require_method(&request, "POST")?;
            handle_analyze_upload(stream, request)
        }
        _ => Err(HttpError::not_found("not found")),
    }
}

fn require_method(request: &HttpRequestHead, expected: &str) -> HttpResult<()> {
    if request.method == expected {
        Ok(())
    } else {
        Err(HttpError::method_not_allowed(format!(
            "{} does not allow {}",
            request.path, request.method
        )))
    }
}

fn handle_analyze(stream: &mut TcpStream, request: HttpRequestHead) -> HttpResult<()> {
    require_json_content_type(&request)?;

    let body = read_body(stream, &request, MAX_JSON_BODY_SIZE)?;
    let payload: AnalyzeHttpRequest = serde_json::from_slice(&body)
        .map_err(|err| HttpError::bad_request(format!("invalid JSON body: {}", err)))?;
    let workspace_root =
        std::env::current_dir().map_err(|err| HttpError::internal_server_error(err.to_string()))?;
    let file = resolve_workspace_capture_path(&workspace_root, &payload.file)?;
    let response = analyze_capture(&AnalysisRequest {
        file: file.to_string_lossy().to_string(),
        ports: normalize_ports(payload.ports.unwrap_or_default()),
        ignore_vlan: payload.ignore_vlan.unwrap_or(false),
    })
    .map_err(|err| HttpError::unprocessable_content(err.to_string()))?;
    let json = serde_json::to_vec_pretty(&response)
        .map_err(|err| HttpError::internal_server_error(err.to_string()))?;

    write_response(stream, "200 OK", "application/json; charset=utf-8", &json)
        .map_err(|err| HttpError::internal_server_error(err.to_string()))
}

fn require_json_content_type(request: &HttpRequestHead) -> HttpResult<()> {
    let content_type = request
        .headers
        .get("content-type")
        .map(String::as_str)
        .unwrap_or("");

    if content_type.starts_with("application/json") {
        Ok(())
    } else {
        Err(HttpError::unsupported_media_type(
            "content-type must be application/json",
        ))
    }
}

fn handle_analyze_upload(stream: &mut TcpStream, request: HttpRequestHead) -> HttpResult<()> {
    let content_length = content_length(&request)?;
    if content_length == 0 {
        return Err(HttpError::bad_request("uploaded file is empty"));
    }
    if content_length > MAX_UPLOAD_BODY_SIZE {
        return Err(HttpError::payload_too_large(format!(
            "uploaded file is too large (max {} MB)",
            MAX_UPLOAD_BODY_SIZE / 1024 / 1024
        )));
    }

    let extension = request
        .headers
        .get("x-file-extension")
        .map(|value| sanitize_extension(value))
        .transpose()?
        .unwrap_or_else(|| "pcap".to_string());
    let display_name = sanitize_display_name(
        request.headers.get("x-file-name").map(String::as_str),
        &extension,
    );
    let ports = request
        .headers
        .get("x-ports")
        .map(|value| parse_ports(value))
        .unwrap_or_default();
    let ignore_vlan = request
        .headers
        .get("x-ignore-vlan")
        .map(|value| parse_bool_header(value))
        .unwrap_or(false);

    let upload_path = build_upload_path(&extension)
        .map_err(|err| HttpError::internal_server_error(err.to_string()))?;
    if let Err(err) = stream_body_to_file(stream, &request, &upload_path, content_length) {
        cleanup_upload(&upload_path);
        return Err(err);
    }

    let analysis = analyze_capture(&AnalysisRequest {
        file: upload_path.to_string_lossy().to_string(),
        ports,
        ignore_vlan,
    });
    cleanup_upload(&upload_path);

    let mut response = analysis.map_err(|err| HttpError::unprocessable_content(err.to_string()))?;
    response.file = display_name;

    let json = serde_json::to_vec_pretty(&response)
        .map_err(|err| HttpError::internal_server_error(err.to_string()))?;
    write_response(stream, "200 OK", "application/json; charset=utf-8", &json)
        .map_err(|err| HttpError::internal_server_error(err.to_string()))
}

fn cleanup_upload(path: &Path) {
    if let Err(err) = fs::remove_file(path) {
        warn!("清理上传临时文件失败 {}: {}", path.display(), err);
    }
}

fn read_request_head(stream: &mut TcpStream) -> HttpResult<HttpRequestHead> {
    let mut buffer = Vec::new();
    let mut temp = [0u8; 4096];
    let headers_end;

    loop {
        let read = stream
            .read(&mut temp)
            .map_err(|err| HttpError::from_read_error("failed to read request headers", err))?;
        if read == 0 {
            return Err(HttpError::bad_request(
                "connection closed before request was complete",
            ));
        }

        buffer.extend_from_slice(&temp[..read]);
        if buffer.len() > MAX_HEADER_SIZE && find_bytes(&buffer, b"\r\n\r\n").is_none() {
            return Err(HttpError::header_fields_too_large(
                "request headers too large",
            ));
        }

        if let Some(pos) = find_bytes(&buffer, b"\r\n\r\n") {
            headers_end = pos;
            break;
        }
    }

    let header_text = String::from_utf8_lossy(&buffer[..headers_end]);
    let mut lines = header_text.split("\r\n");
    let request_line = lines
        .next()
        .ok_or_else(|| HttpError::bad_request("missing request line"))?;
    let mut request_parts = request_line.split_whitespace();
    let method = request_parts
        .next()
        .ok_or_else(|| HttpError::bad_request("missing HTTP method"))?
        .to_string();
    let raw_path = request_parts
        .next()
        .ok_or_else(|| HttpError::bad_request("missing HTTP path"))?;
    let path = raw_path.split('?').next().unwrap_or(raw_path).to_string();

    let mut headers = HashMap::new();
    for line in lines {
        if let Some((name, value)) = line.split_once(':') {
            headers.insert(name.trim().to_ascii_lowercase(), value.trim().to_string());
        }
    }

    Ok(HttpRequestHead {
        method,
        path,
        headers,
        body_prefix: buffer[headers_end + 4..].to_vec(),
    })
}

fn read_body(
    stream: &mut TcpStream,
    request: &HttpRequestHead,
    max_size: usize,
) -> HttpResult<Vec<u8>> {
    let content_length = content_length(request)?;
    if content_length > max_size {
        return Err(HttpError::payload_too_large("request body too large"));
    }

    let mut body = request.body_prefix.clone();
    if body.len() > content_length {
        body.truncate(content_length);
    }

    let mut temp = [0u8; 8192];
    while body.len() < content_length {
        let read = stream
            .read(&mut temp)
            .map_err(|err| HttpError::from_read_error("failed to read request body", err))?;
        if read == 0 {
            return Err(HttpError::bad_request(
                "connection closed before request body was complete",
            ));
        }
        body.extend_from_slice(&temp[..read]);
        if body.len() > max_size {
            return Err(HttpError::payload_too_large("request body too large"));
        }
    }

    body.truncate(content_length);
    Ok(body)
}

fn stream_body_to_file(
    stream: &mut TcpStream,
    request: &HttpRequestHead,
    path: &Path,
    content_length: usize,
) -> HttpResult<()> {
    let mut file = File::create(path).map_err(|err| {
        HttpError::internal_server_error(format!("failed to create upload file: {}", err))
    })?;
    let prefix_len = request.body_prefix.len().min(content_length);
    file.write_all(&request.body_prefix[..prefix_len])
        .map_err(|err| {
            HttpError::internal_server_error(format!("failed to write upload prefix: {}", err))
        })?;

    let mut written = prefix_len;
    let mut temp = [0u8; 65536];
    while written < content_length {
        let target = (content_length - written).min(temp.len());
        let read = stream
            .read(&mut temp[..target])
            .map_err(|err| HttpError::from_read_error("failed to read upload body", err))?;
        if read == 0 {
            return Err(HttpError::bad_request(
                "connection closed before upload was complete",
            ));
        }
        file.write_all(&temp[..read]).map_err(|err| {
            HttpError::internal_server_error(format!("failed to write upload body: {}", err))
        })?;
        written += read;
    }

    file.flush().map_err(|err| {
        HttpError::internal_server_error(format!("failed to flush upload file: {}", err))
    })
}

fn content_length(request: &HttpRequestHead) -> HttpResult<usize> {
    request
        .headers
        .get("content-length")
        .ok_or_else(|| HttpError::length_required("missing content-length"))?
        .parse::<usize>()
        .map_err(|_| HttpError::bad_request("invalid content-length"))
}

fn build_upload_path(extension: &str) -> std::io::Result<PathBuf> {
    let mut dir = std::env::temp_dir();
    dir.push("smtp-analyzer-uploads");
    fs::create_dir_all(&dir)?;

    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_micros();
    let sequence = UPLOAD_COUNTER.fetch_add(1, Ordering::Relaxed);
    let pid = std::process::id();
    dir.push(format!("upload-{stamp}-{pid}-{sequence}.{extension}"));
    Ok(dir)
}

fn validate_bind_host(host: &str) -> Result<()> {
    if host.eq_ignore_ascii_case("localhost") {
        return Ok(());
    }

    match host.parse::<IpAddr>() {
        Ok(ip) if ip.is_loopback() => Ok(()),
        Ok(_) => Err(AnalyzerError::InvalidInput(
            "HTTP 服务仅允许绑定 localhost、127.0.0.1 或 ::1".to_string(),
        )),
        Err(_) => Err(AnalyzerError::InvalidInput(format!(
            "无法识别的监听地址: {}",
            host
        ))),
    }
}

fn resolve_workspace_capture_path(base_dir: &Path, file: &str) -> HttpResult<PathBuf> {
    let trimmed = file.trim();
    if trimmed.is_empty() {
        return Err(HttpError::bad_request("file path is required"));
    }

    let requested = Path::new(trimmed);
    let candidate = if requested.is_absolute() {
        requested.to_path_buf()
    } else {
        base_dir.join(requested)
    };

    let canonical_base = base_dir.canonicalize().map_err(|err| {
        HttpError::internal_server_error(format!("failed to resolve workspace root: {}", err))
    })?;
    let canonical_file = candidate.canonicalize().map_err(|err| match err.kind() {
        std::io::ErrorKind::NotFound => HttpError::not_found("capture file not found"),
        _ => HttpError::internal_server_error(format!("failed to resolve capture path: {}", err)),
    })?;

    if !canonical_file.starts_with(&canonical_base) {
        return Err(HttpError::forbidden(
            "file path must stay within the current working directory",
        ));
    }
    if !canonical_file.is_file() {
        return Err(HttpError::unprocessable_content(
            "capture path must point to a file",
        ));
    }

    validate_capture_extension(&canonical_file)?;
    Ok(canonical_file)
}

fn validate_capture_extension(path: &Path) -> HttpResult<()> {
    let extension = path
        .extension()
        .and_then(|value| value.to_str())
        .map(|value| value.to_ascii_lowercase())
        .ok_or_else(|| {
            HttpError::unprocessable_content("capture file must have a supported extension")
        })?;

    if is_allowed_capture_extension(&extension) {
        Ok(())
    } else {
        Err(HttpError::unprocessable_content(format!(
            "unsupported capture file extension: .{}",
            extension
        )))
    }
}

fn sanitize_extension(value: &str) -> HttpResult<String> {
    let cleaned = value
        .chars()
        .filter(|ch| ch.is_ascii_alphanumeric())
        .collect::<String>()
        .to_ascii_lowercase();

    if cleaned.is_empty() {
        return Err(HttpError::unprocessable_content(
            "upload file extension is required",
        ));
    }

    if is_allowed_capture_extension(&cleaned) {
        Ok(cleaned)
    } else {
        Err(HttpError::unprocessable_content(format!(
            "unsupported upload file extension: .{}",
            cleaned
        )))
    }
}

fn is_allowed_capture_extension(extension: &str) -> bool {
    ALLOWED_CAPTURE_EXTENSIONS.contains(&extension)
}

fn sanitize_display_name(value: Option<&str>, extension: &str) -> String {
    let fallback = format!("browser-upload.{}", extension);
    let Some(raw) = value.map(str::trim).filter(|value| !value.is_empty()) else {
        return fallback;
    };

    let basename = raw.rsplit(['/', '\\']).next().unwrap_or(raw).trim();
    let sanitized = basename
        .chars()
        .filter(|ch| !ch.is_control())
        .collect::<String>();

    if sanitized.is_empty() {
        fallback
    } else {
        sanitized
    }
}

fn parse_bool_header(value: &str) -> bool {
    matches!(
        value.trim().to_ascii_lowercase().as_str(),
        "1" | "true" | "yes" | "on"
    )
}

fn write_error_response(stream: &mut TcpStream, error: &HttpError) -> std::io::Result<()> {
    let body = serde_json::to_vec(&ErrorPayload {
        error: &error.message,
    })
    .unwrap_or_else(|_| br#"{"error":"internal error"}"#.to_vec());
    write_response_with_headers(
        stream,
        error.status,
        "application/json; charset=utf-8",
        &body,
        error.headers,
    )
}

fn write_response(
    stream: &mut TcpStream,
    status: &str,
    content_type: &str,
    body: &[u8],
) -> std::io::Result<()> {
    write_response_with_headers(stream, status, content_type, body, &[])
}

fn write_response_with_headers(
    stream: &mut TcpStream,
    status: &str,
    content_type: &str,
    body: &[u8],
    extra_headers: &[(&str, &str)],
) -> std::io::Result<()> {
    let mut header = format!(
        "HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\nX-Content-Type-Options: nosniff\r\n",
        body.len()
    );

    for (name, value) in extra_headers {
        header.push_str(name);
        header.push_str(": ");
        header.push_str(value);
        header.push_str("\r\n");
    }

    header.push_str("\r\n");
    stream.write_all(header.as_bytes())?;
    stream.write_all(body)?;
    stream.flush()
}

fn find_bytes(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

#[cfg(test)]
mod tests {
    use std::io::{Read, Write};
    use std::net::{Shutdown, TcpListener, TcpStream};
    use std::path::Path;
    use std::thread;
    use std::time::Duration;

    use super::{
        build_upload_path, handle_connection, resolve_workspace_capture_path,
        sanitize_display_name, sanitize_extension, validate_bind_host, write_error_response,
    };

    #[test]
    fn validate_bind_host_accepts_loopback_values() {
        assert!(validate_bind_host("127.0.0.1").is_ok());
        assert!(validate_bind_host("::1").is_ok());
        assert!(validate_bind_host("localhost").is_ok());
    }

    #[test]
    fn validate_bind_host_rejects_non_loopback_values() {
        assert!(validate_bind_host("0.0.0.0").is_err());
        assert!(validate_bind_host("192.168.1.10").is_err());
    }

    #[test]
    fn resolve_workspace_capture_path_accepts_sample_in_workspace() {
        let workspace = Path::new(env!("CARGO_MANIFEST_DIR"));
        let resolved = resolve_workspace_capture_path(workspace, "service_test_sample.pcap")
            .expect("sample capture should be accepted");

        assert!(resolved.ends_with("service_test_sample.pcap"));
    }

    #[test]
    fn resolve_workspace_capture_path_rejects_escape_outside_workspace() {
        let workspace = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        let error = resolve_workspace_capture_path(&workspace, "../service_test_sample.pcap")
            .expect_err("path outside workspace should be rejected");

        assert_eq!(error.status, "403 Forbidden");
    }

    #[test]
    fn sanitize_extension_allows_supported_types_only() {
        assert_eq!(
            sanitize_extension("PCAPNG").expect("pcapng should be allowed"),
            "pcapng"
        );
        assert!(sanitize_extension("txt").is_err());
    }

    #[test]
    fn sanitize_display_name_strips_path_components() {
        assert_eq!(
            sanitize_display_name(Some(r"C:\captures\sample.pcap"), "pcap"),
            "sample.pcap"
        );
        assert_eq!(
            sanitize_display_name(Some("/tmp/evil.pcapng"), "pcapng"),
            "evil.pcapng"
        );
    }

    #[test]
    fn build_upload_path_produces_unique_names() {
        let first = build_upload_path("pcap").expect("first path should be created");
        let second = build_upload_path("pcap").expect("second path should be created");

        assert_ne!(first, second);
    }

    #[test]
    fn handle_connection_returns_health_response() {
        let response = execute_raw_request(
            b"GET /health HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
        );

        assert!(response.starts_with("HTTP/1.1 200 OK"));
        assert!(response.contains(r#"{"status":"ok"}"#));
    }

    #[test]
    fn handle_connection_returns_method_not_allowed_for_known_route() {
        let response = execute_raw_request(
            b"POST /health HTTP/1.1\r\nHost: localhost\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        );

        assert!(response.starts_with("HTTP/1.1 405 Method Not Allowed"));
        assert!(response.contains("Allow: GET, POST, OPTIONS"));
    }

    #[test]
    fn handle_connection_returns_unsupported_media_type_for_non_json_analyze_requests() {
        let response = execute_raw_request(
            b"POST /analyze HTTP/1.1\r\nHost: localhost\r\nContent-Type: text/plain\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}",
        );

        assert!(response.starts_with("HTTP/1.1 415 Unsupported Media Type"));
        assert!(response.contains("application/json"));
    }

    #[test]
    fn handle_connection_returns_length_required_without_content_length() {
        let response = execute_raw_request(
            b"POST /analyze-upload HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
        );

        assert!(response.starts_with("HTTP/1.1 411 Length Required"));
        assert!(response.contains("missing content-length"));
    }

    fn execute_raw_request(raw_request: &[u8]) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").expect("listener should bind");
        let address = listener
            .local_addr()
            .expect("listener should have a local address");

        let server = thread::spawn(move || {
            let (mut server_stream, _) =
                listener.accept().expect("server should accept one client");
            server_stream
                .set_read_timeout(Some(Duration::from_secs(2)))
                .expect("read timeout should be set");
            server_stream
                .set_write_timeout(Some(Duration::from_secs(2)))
                .expect("write timeout should be set");

            if let Err(err) = handle_connection(&mut server_stream) {
                write_error_response(&mut server_stream, &err)
                    .expect("server should be able to send error response");
            }
        });

        let mut client = TcpStream::connect(address).expect("client should connect");
        client
            .write_all(raw_request)
            .expect("client should write request");
        client
            .shutdown(Shutdown::Write)
            .expect("client should close request body");

        let mut response = String::new();
        client
            .read_to_string(&mut response)
            .expect("client should read response");

        server.join().expect("server thread should finish");
        response
    }
}
