//! 本地 HTTP 服务

use std::collections::HashMap;
use std::fs::{self, File};
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use log::{error, info, warn};
use serde::{Deserialize, Serialize};

use crate::app::{analyze_capture, normalize_ports, parse_ports, AnalysisRequest};
use crate::error::Result;

const MAX_HEADER_SIZE: usize = 64 * 1024;
const MAX_JSON_BODY_SIZE: usize = 8 * 1024 * 1024;
const MAX_UPLOAD_BODY_SIZE: usize = 1024 * 1024 * 1024;
const INDEX_HTML: &str = include_str!("../web/index.html");
const APP_JS: &str = include_str!("../web/app.js");
const STYLES_CSS: &str = include_str!("../web/styles.css");

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

pub fn serve(host: &str, port: u16) -> Result<()> {
    let bind_addr = format!("{host}:{port}");
    let listener = TcpListener::bind(&bind_addr)?;
    info!("HTTP 服务已启动: http://{}", bind_addr);
    info!("健康检查: http://{}/health", bind_addr);
    info!("上传分析接口: POST http://{}/analyze-upload", bind_addr);

    for stream in listener.incoming() {
        match stream {
            Ok(mut stream) => {
                if let Err(err) = handle_connection(&mut stream) {
                    warn!("处理 HTTP 请求失败: {}", err);
                    let body = serde_json::to_vec(&ErrorPayload { error: &err })
                        .unwrap_or_else(|_| br#"{"error":"internal error"}"#.to_vec());
                    let _ = write_response(
                        &mut stream,
                        "400 Bad Request",
                        "application/json; charset=utf-8",
                        &body,
                    );
                }
            }
            Err(err) => {
                error!("接受连接失败: {}", err);
            }
        }
    }

    Ok(())
}

fn handle_connection(stream: &mut TcpStream) -> std::result::Result<(), String> {
    let request = read_request_head(stream)?;

    match (request.method.as_str(), request.path.as_str()) {
        ("OPTIONS", _) => write_response(stream, "204 No Content", "text/plain; charset=utf-8", b"")
            .map_err(|err| err.to_string()),
        ("GET", "/") => write_response(
            stream,
            "200 OK",
            "text/html; charset=utf-8",
            INDEX_HTML.as_bytes(),
        )
        .map_err(|err| err.to_string()),
        ("GET", "/app.js") => write_response(
            stream,
            "200 OK",
            "application/javascript; charset=utf-8",
            APP_JS.as_bytes(),
        )
        .map_err(|err| err.to_string()),
        ("GET", "/styles.css") => write_response(
            stream,
            "200 OK",
            "text/css; charset=utf-8",
            STYLES_CSS.as_bytes(),
        )
        .map_err(|err| err.to_string()),
        ("GET", "/health") => {
            let body = serde_json::to_vec(&HealthPayload { status: "ok" })
                .map_err(|err| err.to_string())?;
            write_response(stream, "200 OK", "application/json; charset=utf-8", &body)
                .map_err(|err| err.to_string())
        }
        ("POST", "/analyze") => handle_analyze(stream, request),
        ("POST", "/analyze-upload") => handle_analyze_upload(stream, request),
        _ => {
            let body = serde_json::to_vec(&ErrorPayload { error: "not found" })
                .map_err(|err| err.to_string())?;
            write_response(
                stream,
                "404 Not Found",
                "application/json; charset=utf-8",
                &body,
            )
            .map_err(|err| err.to_string())
        }
    }
}

fn handle_analyze(
    stream: &mut TcpStream,
    request: HttpRequestHead,
) -> std::result::Result<(), String> {
    let content_type = request
        .headers
        .get("content-type")
        .map(String::as_str)
        .unwrap_or("");
    if !content_type.starts_with("application/json") {
        let body = serde_json::to_vec(&ErrorPayload {
            error: "content-type must be application/json",
        })
        .map_err(|err| err.to_string())?;
        return write_response(
            stream,
            "415 Unsupported Media Type",
            "application/json; charset=utf-8",
            &body,
        )
        .map_err(|err| err.to_string());
    }

    let body = read_body(stream, &request, MAX_JSON_BODY_SIZE)?;
    let payload: AnalyzeHttpRequest =
        serde_json::from_slice(&body).map_err(|err| format!("invalid JSON body: {}", err))?;
    let response = analyze_capture(&AnalysisRequest {
        file: payload.file,
        ports: normalize_ports(payload.ports.unwrap_or_default()),
        ignore_vlan: payload.ignore_vlan.unwrap_or(false),
    })
    .map_err(|err| err.to_string())?;
    let json = serde_json::to_vec_pretty(&response).map_err(|err| err.to_string())?;

    write_response(stream, "200 OK", "application/json; charset=utf-8", &json)
        .map_err(|err| err.to_string())
}

fn handle_analyze_upload(
    stream: &mut TcpStream,
    request: HttpRequestHead,
) -> std::result::Result<(), String> {
    let content_length = content_length(&request)?;
    if content_length == 0 {
        return Err("uploaded file is empty".to_string());
    }
    if content_length > MAX_UPLOAD_BODY_SIZE {
        return Err(format!(
            "uploaded file is too large (max {} MB)",
            MAX_UPLOAD_BODY_SIZE / 1024 / 1024
        ));
    }

    let extension = request
        .headers
        .get("x-file-extension")
        .map(|value| sanitize_extension(value))
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| "pcap".to_string());
    let display_name = request
        .headers
        .get("x-file-name")
        .cloned()
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| format!("browser-upload.{}", extension));
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

    let upload_path = build_upload_path(&extension).map_err(|err| err.to_string())?;
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

    let mut response = analysis.map_err(|err| err.to_string())?;
    response.file = display_name;

    let json = serde_json::to_vec_pretty(&response).map_err(|err| err.to_string())?;
    write_response(stream, "200 OK", "application/json; charset=utf-8", &json)
        .map_err(|err| err.to_string())
}

fn cleanup_upload(path: &Path) {
    if let Err(err) = fs::remove_file(path) {
        warn!("清理上传临时文件失败 {}: {}", path.display(), err);
    }
}

fn read_request_head(stream: &mut TcpStream) -> std::result::Result<HttpRequestHead, String> {
    let mut buffer = Vec::new();
    let mut temp = [0u8; 4096];
    let headers_end;

    loop {
        let read = stream.read(&mut temp).map_err(|err| err.to_string())?;
        if read == 0 {
            return Err("connection closed before request was complete".to_string());
        }

        buffer.extend_from_slice(&temp[..read]);
        if buffer.len() > MAX_HEADER_SIZE && find_bytes(&buffer, b"\r\n\r\n").is_none() {
            return Err("request headers too large".to_string());
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
        .ok_or_else(|| "missing request line".to_string())?;
    let mut request_parts = request_line.split_whitespace();
    let method = request_parts
        .next()
        .ok_or_else(|| "missing HTTP method".to_string())?
        .to_string();
    let raw_path = request_parts
        .next()
        .ok_or_else(|| "missing HTTP path".to_string())?;
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
) -> std::result::Result<Vec<u8>, String> {
    let content_length = content_length(request)?;
    if content_length > max_size {
        return Err("request body too large".to_string());
    }

    let mut body = request.body_prefix.clone();
    if body.len() > content_length {
        body.truncate(content_length);
    }

    let mut temp = [0u8; 8192];
    while body.len() < content_length {
        let read = stream.read(&mut temp).map_err(|err| err.to_string())?;
        if read == 0 {
            return Err("connection closed before request body was complete".to_string());
        }
        body.extend_from_slice(&temp[..read]);
        if body.len() > max_size {
            return Err("request body too large".to_string());
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
) -> std::result::Result<(), String> {
    let mut file = File::create(path).map_err(|err| err.to_string())?;
    let prefix_len = request.body_prefix.len().min(content_length);
    file.write_all(&request.body_prefix[..prefix_len])
        .map_err(|err| err.to_string())?;

    let mut written = prefix_len;
    let mut temp = [0u8; 65536];
    while written < content_length {
        let target = (content_length - written).min(temp.len());
        let read = stream
            .read(&mut temp[..target])
            .map_err(|err| err.to_string())?;
        if read == 0 {
            return Err("connection closed before upload was complete".to_string());
        }
        file.write_all(&temp[..read]).map_err(|err| err.to_string())?;
        written += read;
    }

    file.flush().map_err(|err| err.to_string())
}

fn content_length(request: &HttpRequestHead) -> std::result::Result<usize, String> {
    request
        .headers
        .get("content-length")
        .ok_or_else(|| "missing content-length".to_string())?
        .parse::<usize>()
        .map_err(|_| "invalid content-length".to_string())
}

fn build_upload_path(extension: &str) -> std::io::Result<PathBuf> {
    let mut dir = std::env::temp_dir();
    dir.push("smtp-analyzer-uploads");
    fs::create_dir_all(&dir)?;

    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis();
    dir.push(format!("upload-{}.{}", stamp, extension));
    Ok(dir)
}

fn sanitize_extension(value: &str) -> String {
    let cleaned = value
        .chars()
        .filter(|ch| ch.is_ascii_alphanumeric())
        .collect::<String>()
        .to_ascii_lowercase();

    if cleaned.is_empty() {
        "pcap".to_string()
    } else {
        cleaned
    }
}

fn parse_bool_header(value: &str) -> bool {
    matches!(
        value.trim().to_ascii_lowercase().as_str(),
        "1" | "true" | "yes" | "on"
    )
}

fn write_response(
    stream: &mut TcpStream,
    status: &str,
    content_type: &str,
    body: &[u8],
) -> std::io::Result<()> {
    let header = format!(
        "HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\nAccess-Control-Allow-Origin: *\r\nAccess-Control-Allow-Methods: GET, POST, OPTIONS\r\nAccess-Control-Allow-Headers: Content-Type, X-Ports, X-Ignore-Vlan, X-File-Extension, X-File-Name\r\n\r\n",
        body.len()
    );
    stream.write_all(header.as_bytes())?;
    stream.write_all(body)?;
    stream.flush()
}

fn find_bytes(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}
