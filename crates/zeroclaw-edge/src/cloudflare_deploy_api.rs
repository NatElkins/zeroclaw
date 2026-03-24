//! Helpers for translating Wrangler-style deploy arguments into Cloudflare API
//! deployment payloads.

use anyhow::{anyhow, bail, Result};
use serde_json::{json, Value};

/// One version traffic allocation entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VersionTraffic {
    pub version_id: String,
    pub percentage: u8,
}

/// Parsed deployment request from a `wrangler versions deploy`-style command.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeployRequest {
    pub worker_name: String,
    pub versions: Vec<VersionTraffic>,
    pub message: Option<String>,
}

/// Parse command program/args emitted by `CloudflareWranglerTrafficClient` into
/// a strongly-typed deploy request suitable for the Cloudflare Deployments API.
pub fn parse_wrangler_versions_deploy(program: &str, args: &[String]) -> Result<DeployRequest> {
    let normalized = normalize_args(program, args)?;
    if normalized.len() < 4 {
        bail!("wrangler versions deploy args are incomplete");
    }
    if normalized[0] != "versions" || normalized[1] != "deploy" {
        bail!("expected wrangler versions deploy command");
    }

    let mut versions = Vec::new();
    let mut worker_name: Option<String> = None;
    let mut message: Option<String> = None;
    let mut i = 2;
    while i < normalized.len() {
        let token = &normalized[i];
        if let Some(spec) = parse_version_spec(token)? {
            versions.push(spec);
            i += 1;
            continue;
        }

        match token.as_str() {
            "--name" => {
                let value = normalized
                    .get(i + 1)
                    .ok_or_else(|| anyhow!("--name requires a value"))?;
                worker_name = Some(value.clone());
                i += 2;
            }
            "--message" => {
                let value = normalized
                    .get(i + 1)
                    .ok_or_else(|| anyhow!("--message requires a value"))?;
                message = Some(value.clone());
                i += 2;
            }
            _ => {
                i += 1;
            }
        }
    }

    if versions.is_empty() {
        bail!("no version traffic specs found");
    }
    let total: u16 = versions.iter().map(|v| v.percentage as u16).sum();
    if total != 100 {
        bail!("traffic percentages must sum to 100, got {total}");
    }

    let worker_name = worker_name.ok_or_else(|| anyhow!("missing --name worker name"))?;
    if worker_name.trim().is_empty() {
        bail!("worker name must not be empty");
    }

    Ok(DeployRequest {
        worker_name,
        versions,
        message,
    })
}

/// Build the JSON payload used by Cloudflare's deployments API:
/// `POST /accounts/{account_id}/workers/scripts/{script_name}/deployments`.
pub fn build_deployments_api_body(request: &DeployRequest) -> Value {
    let versions = request
        .versions
        .iter()
        .map(|v| json!({ "version_id": v.version_id, "percentage": v.percentage }))
        .collect::<Vec<_>>();

    match request.message.as_deref() {
        Some(message) if !message.trim().is_empty() => json!({
            "strategy": "percentage",
            "versions": versions,
            "annotations": {
                "workers/message": message
            }
        }),
        _ => json!({
            "strategy": "percentage",
            "versions": versions
        }),
    }
}

fn normalize_args(program: &str, args: &[String]) -> Result<Vec<String>> {
    match program {
        "wrangler" => Ok(args.to_vec()),
        "npx" => {
            let idx = args
                .iter()
                .position(|a| a == "wrangler")
                .ok_or_else(|| anyhow!("npx invocation missing wrangler token"))?;
            Ok(args[idx + 1..].to_vec())
        }
        other => bail!("unsupported program for wrangler deploy parsing: {other}"),
    }
}

fn parse_version_spec(token: &str) -> Result<Option<VersionTraffic>> {
    let Some((version_id, percent)) = token.split_once('@') else {
        return Ok(None);
    };
    if !percent.ends_with('%') {
        return Ok(None);
    }
    if version_id.trim().is_empty() {
        bail!("version id must not be empty");
    }
    let raw = &percent[..percent.len() - 1];
    let percentage: u8 = raw
        .parse()
        .map_err(|_| anyhow!("invalid percentage in token: {token}"))?;
    if percentage > 100 {
        bail!("percentage out of range in token: {token}");
    }
    Ok(Some(VersionTraffic {
        version_id: version_id.to_string(),
        percentage,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_wrangler_versions_deploy_args() {
        let args = vec![
            "versions".to_string(),
            "deploy".to_string(),
            "canary-v2@25%".to_string(),
            "stable-v1@75%".to_string(),
            "--name".to_string(),
            "edge-smoke".to_string(),
            "--message".to_string(),
            "zc canary".to_string(),
            "--yes".to_string(),
        ];
        let req = parse_wrangler_versions_deploy("wrangler", &args).unwrap();
        assert_eq!(req.worker_name, "edge-smoke");
        assert_eq!(req.versions.len(), 2);
        assert_eq!(
            req.versions[0],
            VersionTraffic {
                version_id: "canary-v2".to_string(),
                percentage: 25
            }
        );
        assert_eq!(req.message.as_deref(), Some("zc canary"));
    }

    #[test]
    fn parses_npx_wrapped_wrangler_args() {
        let args = vec![
            "--yes".to_string(),
            "wrangler".to_string(),
            "versions".to_string(),
            "deploy".to_string(),
            "a@40%".to_string(),
            "b@60%".to_string(),
            "--name".to_string(),
            "worker-a".to_string(),
            "--yes".to_string(),
        ];
        let req = parse_wrangler_versions_deploy("npx", &args).unwrap();
        assert_eq!(req.worker_name, "worker-a");
        assert_eq!(req.versions.len(), 2);
    }

    #[test]
    fn rejects_non_100_traffic_total() {
        let args = vec![
            "versions".to_string(),
            "deploy".to_string(),
            "a@10%".to_string(),
            "b@20%".to_string(),
            "--name".to_string(),
            "worker-a".to_string(),
        ];
        let err = parse_wrangler_versions_deploy("wrangler", &args).unwrap_err();
        assert!(err.to_string().contains("sum to 100"));
    }

    #[test]
    fn builds_expected_api_body() {
        let req = DeployRequest {
            worker_name: "edge-smoke".to_string(),
            versions: vec![
                VersionTraffic {
                    version_id: "canary-v2".to_string(),
                    percentage: 25,
                },
                VersionTraffic {
                    version_id: "stable-v1".to_string(),
                    percentage: 75,
                },
            ],
            message: Some("hello".to_string()),
        };
        let body = build_deployments_api_body(&req);
        assert_eq!(body["strategy"], "percentage");
        assert_eq!(body["versions"][0]["version_id"], "canary-v2");
        assert_eq!(body["versions"][0]["percentage"], 25);
        assert_eq!(body["annotations"]["workers/message"], "hello");
    }
}
