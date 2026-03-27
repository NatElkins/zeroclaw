//! Capability-fallback delegation proxy.
//!
//! This tool wrapper preserves a tool's public name/schema while forwarding
//! execution to the `delegate` tool when the local runtime lacks required
//! capabilities (for example, shell/filesystem access in constrained runtimes).

use std::sync::Arc;

use async_trait::async_trait;
use serde_json::json;

use crate::tools::traits::{Tool, ToolResult};

/// Tool proxy that forwards calls to a named delegate agent.
pub struct CapabilityDelegatingTool {
    name: String,
    description: String,
    parameters: serde_json::Value,
    delegate_agent: String,
    delegate_tool: Arc<dyn Tool>,
}

impl CapabilityDelegatingTool {
    /// Build a capability-fallback proxy from a source tool spec.
    pub fn new(
        source_tool: Arc<dyn Tool>,
        delegate_agent: String,
        delegate_tool: Arc<dyn Tool>,
    ) -> Self {
        Self {
            name: source_tool.name().to_string(),
            description: source_tool.description().to_string(),
            parameters: source_tool.parameters_schema(),
            delegate_agent,
            delegate_tool,
        }
    }

    fn build_delegate_prompt(tool_name: &str, args: &serde_json::Value) -> String {
        let args_json = serde_json::to_string_pretty(args).unwrap_or_else(|_| args.to_string());
        format!(
            "ZeroClaw capability-fallback execution request.\n\
             Execute exactly one tool call named '{tool_name}' using these JSON arguments:\n\n\
             {args_json}\n\n\
             Return the tool result."
        )
    }
}

#[async_trait]
impl Tool for CapabilityDelegatingTool {
    fn name(&self) -> &str {
        &self.name
    }

    fn description(&self) -> &str {
        &self.description
    }

    fn parameters_schema(&self) -> serde_json::Value {
        self.parameters.clone()
    }

    async fn execute(&self, args: serde_json::Value) -> anyhow::Result<ToolResult> {
        let delegate_agent = self.delegate_agent.trim();
        if delegate_agent.is_empty() {
            return Ok(ToolResult {
                success: false,
                output: String::new(),
                error: Some(
                    "Capability delegation is misconfigured: delegate agent is empty".into(),
                ),
            });
        }

        let prompt = Self::build_delegate_prompt(&self.name, &args);
        let delegated = self
            .delegate_tool
            .execute(json!({
                "agent": delegate_agent,
                "prompt": prompt,
            }))
            .await?;

        if delegated.success {
            return Ok(ToolResult {
                success: true,
                output: delegated.output,
                error: None,
            });
        }

        let reason = delegated.error.unwrap_or_else(|| {
            if delegated.output.trim().is_empty() {
                format!(
                    "Capability fallback delegation failed for tool '{}'",
                    self.name
                )
            } else {
                delegated.output
            }
        });

        Ok(ToolResult {
            success: false,
            output: String::new(),
            error: Some(reason),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::sync::Mutex;

    struct StubTool {
        name: String,
        description: String,
        schema: serde_json::Value,
        result: ToolResult,
        observed_args: Arc<Mutex<Vec<serde_json::Value>>>,
    }

    impl StubTool {
        fn new(
            name: &str,
            description: &str,
            schema: serde_json::Value,
            result: ToolResult,
            observed_args: Arc<Mutex<Vec<serde_json::Value>>>,
        ) -> Self {
            Self {
                name: name.to_string(),
                description: description.to_string(),
                schema,
                result,
                observed_args,
            }
        }
    }

    #[async_trait]
    impl Tool for StubTool {
        fn name(&self) -> &str {
            &self.name
        }

        fn description(&self) -> &str {
            &self.description
        }

        fn parameters_schema(&self) -> serde_json::Value {
            self.schema.clone()
        }

        async fn execute(&self, args: serde_json::Value) -> anyhow::Result<ToolResult> {
            self.observed_args.lock().unwrap().push(args);
            Ok(self.result.clone())
        }
    }

    #[tokio::test]
    async fn capability_delegate_forwards_call_to_delegate_tool() {
        let observed = Arc::new(Mutex::new(Vec::new()));

        let source: Arc<dyn Tool> = Arc::new(StubTool::new(
            "shell",
            "Execute shell commands",
            json!({"type":"object","properties":{"command":{"type":"string"}},"required":["command"]}),
            ToolResult {
                success: true,
                output: String::new(),
                error: None,
            },
            Arc::new(Mutex::new(Vec::new())),
        ));
        let delegate: Arc<dyn Tool> = Arc::new(StubTool::new(
            "delegate",
            "Delegate",
            json!({"type":"object"}),
            ToolResult {
                success: true,
                output: "delegated-ok".to_string(),
                error: None,
            },
            Arc::clone(&observed),
        ));

        let proxy = CapabilityDelegatingTool::new(source, "native_worker".to_string(), delegate);

        let result = proxy
            .execute(json!({"command": "ls -la"}))
            .await
            .expect("proxy execution should return result");

        assert!(result.success);
        assert_eq!(result.output, "delegated-ok");

        let calls = observed.lock().unwrap();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0]["agent"], "native_worker");
        let prompt = calls[0]["prompt"]
            .as_str()
            .expect("delegate prompt must be string");
        assert!(prompt.contains("named 'shell'"));
        assert!(prompt.contains("ls -la"));
    }

    #[tokio::test]
    async fn capability_delegate_propagates_delegate_failure_reason() {
        let source: Arc<dyn Tool> = Arc::new(StubTool::new(
            "file_read",
            "Read files",
            json!({"type":"object"}),
            ToolResult {
                success: true,
                output: String::new(),
                error: None,
            },
            Arc::new(Mutex::new(Vec::new())),
        ));
        let delegate: Arc<dyn Tool> = Arc::new(StubTool::new(
            "delegate",
            "Delegate",
            json!({"type":"object"}),
            ToolResult {
                success: false,
                output: String::new(),
                error: Some("policy denied".to_string()),
            },
            Arc::new(Mutex::new(Vec::new())),
        ));

        let proxy = CapabilityDelegatingTool::new(source, "native_worker".to_string(), delegate);

        let result = proxy
            .execute(json!({"path": "Cargo.toml"}))
            .await
            .expect("proxy execution should return result");

        assert!(!result.success);
        assert_eq!(result.error.as_deref(), Some("policy denied"));
    }
}
