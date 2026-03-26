use std::collections::{BTreeSet, HashMap};
use std::env;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::process::Command;

use anyhow::{anyhow, bail, Context, Result};
use serde_json::Value;
use zeroclaw_edge::delegate_http::{
    handle_native_delegate_http_request, DelegationAuthToken, NativeDelegateHttpRequest,
    NativeDelegateServicePolicy,
};
use zeroclaw_edge::{
    DelegatedTool, NativeWorkerHandler, NativeWorkerRequest, NativeWorkerResponse,
};

const ENV_BIND_ADDR: &str = "ZEROCLAW_EDGE_DELEGATE_BIND_ADDR";
const ENV_AUTH_TOKEN: &str = "ZEROCLAW_EDGE_DELEGATE_AUTH_TOKEN";
const ENV_ALLOWED_TOOLS: &str = "ZEROCLAW_EDGE_DELEGATE_ALLOWED_TOOLS";
const ENV_SHELL_BIN: &str = "ZEROCLAW_EDGE_DELEGATE_SHELL_BIN";
const DEFAULT_BIND_ADDR: &str = "127.0.0.1:8091";
const DEFAULT_ALLOWED_TOOLS: &str = "shell";
const DEFAULT_SHELL_BIN: &str = "/bin/sh";

#[derive(Debug, Clone, PartialEq, Eq)]
struct ServiceConfig {
    bind_addr: String,
    auth_token: DelegationAuthToken,
    allowed_tools: BTreeSet<DelegatedTool>,
    shell_bin: String,
}

impl ServiceConfig {
    fn from_env() -> Result<Self> {
        let bind_addr = env::var(ENV_BIND_ADDR)
            .unwrap_or_else(|_| DEFAULT_BIND_ADDR.to_string())
            .trim()
            .to_string();
        if bind_addr.is_empty() {
            bail!("{ENV_BIND_ADDR} must not be empty");
        }

        let auth_token_raw = env::var(ENV_AUTH_TOKEN)
            .context(format!("missing required env var {ENV_AUTH_TOKEN}"))?;
        let auth_token = DelegationAuthToken::new(auth_token_raw)
            .context(format!("invalid {ENV_AUTH_TOKEN}"))?;

        let allowed_tools_raw =
            env::var(ENV_ALLOWED_TOOLS).unwrap_or_else(|_| DEFAULT_ALLOWED_TOOLS.to_string());
        let allowed_tools = parse_tool_allowlist(allowed_tools_raw.as_str())
            .context(format!("invalid {ENV_ALLOWED_TOOLS}"))?;

        let shell_bin = env::var(ENV_SHELL_BIN)
            .unwrap_or_else(|_| DEFAULT_SHELL_BIN.to_string())
            .trim()
            .to_string();
        if shell_bin.is_empty() {
            bail!("{ENV_SHELL_BIN} must not be empty");
        }

        Ok(Self {
            bind_addr,
            auth_token,
            allowed_tools,
            shell_bin,
        })
    }
}

fn parse_tool(raw: &str) -> Result<DelegatedTool> {
    match raw.trim() {
        "shell" => Ok(DelegatedTool::Shell),
        "file_read" => Ok(DelegatedTool::FileRead),
        "file_write" => Ok(DelegatedTool::FileWrite),
        "file_edit" => Ok(DelegatedTool::FileEdit),
        "glob_search" => Ok(DelegatedTool::GlobSearch),
        "content_search" => Ok(DelegatedTool::ContentSearch),
        "git_operations" => Ok(DelegatedTool::GitOperations),
        other => Err(anyhow!("unsupported delegated tool '{other}'")),
    }
}

fn parse_tool_allowlist(raw: &str) -> Result<BTreeSet<DelegatedTool>> {
    let mut tools = BTreeSet::new();
    for item in raw.split(',') {
        let value = item.trim();
        if value.is_empty() {
            continue;
        }
        tools.insert(parse_tool(value)?);
    }
    if tools.is_empty() {
        bail!("delegated tool allowlist must include at least one tool");
    }
    Ok(tools)
}

#[derive(Debug, Clone)]
struct DelegateHandler {
    shell_bin: String,
}

impl DelegateHandler {
    fn shell_command(args: &Value) -> Result<&str> {
        args.get("command")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| anyhow!("shell tool args.command must be a non-empty string"))
    }
}

impl NativeWorkerHandler for DelegateHandler {
    fn handle(&self, request: NativeWorkerRequest) -> Result<NativeWorkerResponse> {
        match request.tool {
            DelegatedTool::Shell => {
                let command = Self::shell_command(&request.args)?;
                let output = Command::new(self.shell_bin.as_str())
                    .arg("-lc")
                    .arg(command)
                    .output()
                    .with_context(|| {
                        format!(
                            "failed executing shell command with {}: {}",
                            self.shell_bin, command
                        )
                    })?;

                let stdout = String::from_utf8_lossy(&output.stdout).to_string();
                let stderr = String::from_utf8_lossy(&output.stderr).to_string();
                if output.status.success() {
                    Ok(NativeWorkerResponse {
                        success: true,
                        output: stdout,
                        error: None,
                    })
                } else {
                    let code = output.status.code().unwrap_or(-1);
                    let detail = if stderr.trim().is_empty() {
                        stdout.trim().to_string()
                    } else {
                        stderr.trim().to_string()
                    };
                    Ok(NativeWorkerResponse {
                        success: false,
                        output: stdout,
                        error: Some(format!("shell command failed (exit={code}): {detail}")),
                    })
                }
            }
            other => Ok(NativeWorkerResponse {
                success: false,
                output: String::new(),
                error: Some(format!(
                    "native service does not implement delegated tool '{}'",
                    other.as_str()
                )),
            }),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct HttpRequest {
    method: String,
    path: String,
    headers: HashMap<String, String>,
    body: Vec<u8>,
}

fn parse_http_request(stream: &mut TcpStream) -> Result<HttpRequest> {
    let mut buffer = Vec::new();
    let mut header_end = None;
    while header_end.is_none() {
        let mut chunk = [0u8; 2048];
        let bytes = stream
            .read(&mut chunk)
            .context("failed reading request bytes")?;
        if bytes == 0 {
            break;
        }
        buffer.extend_from_slice(&chunk[..bytes]);
        if let Some(pos) = buffer.windows(4).position(|window| window == b"\r\n\r\n") {
            header_end = Some(pos + 4);
        }
        if buffer.len() > 1024 * 1024 {
            bail!("request headers exceeded 1MiB");
        }
    }

    let header_end = header_end.ok_or_else(|| anyhow!("incomplete HTTP request headers"))?;
    let header_bytes = &buffer[..header_end];
    let header_text = std::str::from_utf8(header_bytes).context("request headers must be UTF-8")?;
    let mut lines = header_text.split("\r\n").filter(|line| !line.is_empty());

    let request_line = lines
        .next()
        .ok_or_else(|| anyhow!("missing HTTP request line"))?;
    let mut request_parts = request_line.split_whitespace();
    let method = request_parts
        .next()
        .ok_or_else(|| anyhow!("missing request method"))?
        .to_string();
    let path = request_parts
        .next()
        .ok_or_else(|| anyhow!("missing request path"))?
        .to_string();

    let mut headers = HashMap::new();
    for line in lines {
        if let Some((name, value)) = line.split_once(':') {
            headers.insert(name.trim().to_ascii_lowercase(), value.trim().to_string());
        }
    }

    let content_length = headers
        .get("content-length")
        .map(|value| value.parse::<usize>())
        .transpose()
        .context("invalid content-length header")?
        .unwrap_or(0);

    let mut body = buffer[header_end..].to_vec();
    while body.len() < content_length {
        let mut chunk = vec![0u8; content_length - body.len()];
        let bytes = stream
            .read(chunk.as_mut_slice())
            .context("failed reading request body")?;
        if bytes == 0 {
            break;
        }
        body.extend_from_slice(&chunk[..bytes]);
    }
    body.truncate(content_length);

    Ok(HttpRequest {
        method,
        path,
        headers,
        body,
    })
}

fn write_json_response(stream: &mut TcpStream, status_code: u16, body: &str) -> Result<()> {
    let status_text = match status_code {
        200 => "OK",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        500 => "Internal Server Error",
        _ => "OK",
    };
    let response = format!(
        "HTTP/1.1 {status_code} {status_text}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        body.len(),
        body
    );
    stream
        .write_all(response.as_bytes())
        .context("failed writing HTTP response")?;
    stream.flush().context("failed flushing HTTP response")?;
    Ok(())
}

fn write_not_found(stream: &mut TcpStream) -> Result<()> {
    let body = r#"{"success":false,"output":"","error":"not found"}"#;
    write_json_response(stream, 404, body)
}

fn run() -> Result<()> {
    let config = ServiceConfig::from_env()?;
    let policy = NativeDelegateServicePolicy::new(config.auth_token.clone(), config.allowed_tools);
    let handler = DelegateHandler {
        shell_bin: config.shell_bin.clone(),
    };
    let listener = TcpListener::bind(config.bind_addr.as_str())
        .with_context(|| format!("failed binding {}", config.bind_addr))?;

    eprintln!(
        "native delegate service listening on {} (tools={:?})",
        config.bind_addr, policy.allowed_tools
    );

    for stream in listener.incoming() {
        let mut stream = match stream {
            Ok(stream) => stream,
            Err(err) => {
                eprintln!("failed accepting connection: {err}");
                continue;
            }
        };

        let request = match parse_http_request(&mut stream) {
            Ok(request) => request,
            Err(err) => {
                let body = format!(
                    "{{\"success\":false,\"output\":\"\",\"error\":\"invalid request: {}\"}}",
                    err
                );
                let _ = write_json_response(&mut stream, 400, body.as_str());
                continue;
            }
        };

        if request.path != "/delegate/execute" {
            if let Err(err) = write_not_found(&mut stream) {
                eprintln!("failed writing not-found response: {err}");
            }
            continue;
        }

        let wire_request = NativeDelegateHttpRequest::new(
            request.method,
            request.headers.get("authorization").cloned(),
            String::from_utf8(request.body).unwrap_or_else(|_| String::new()),
        );
        let response = handle_native_delegate_http_request(&policy, wire_request, &handler);
        if let Err(err) =
            write_json_response(&mut stream, response.status_code, response.body.as_str())
        {
            eprintln!("failed writing delegate response: {err}");
        }
    }
    Ok(())
}

fn main() {
    if let Err(err) = run() {
        eprintln!("native delegate service failed: {err:#}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_tool_allowlist_rejects_empty_and_unknown() {
        assert!(parse_tool_allowlist(" ").is_err());
        assert!(parse_tool_allowlist("shell,bad").is_err());
    }

    #[test]
    fn parse_tool_allowlist_deduplicates() {
        let parsed = parse_tool_allowlist("shell,file_read,shell").unwrap();
        assert_eq!(
            parsed,
            BTreeSet::from([DelegatedTool::Shell, DelegatedTool::FileRead])
        );
    }

    #[test]
    fn shell_handler_requires_non_empty_command() {
        let handler = DelegateHandler {
            shell_bin: DEFAULT_SHELL_BIN.to_string(),
        };
        let req = NativeWorkerRequest {
            session_id: None,
            tool: DelegatedTool::Shell,
            args: serde_json::json!({"command": " "}),
        };
        let err = handler
            .handle(req)
            .err()
            .map(|e| e.to_string())
            .unwrap_or_default();
        assert!(err.contains("non-empty"));
    }
}
