pub mod docker;
pub mod native;
pub mod traits;
#[cfg(feature = "runtime-wasm")]
pub mod wasm;

pub use docker::DockerRuntime;
pub use native::NativeRuntime;
pub use traits::RuntimeAdapter;
#[cfg(feature = "runtime-wasm")]
pub use wasm::WasmRuntime;

use crate::config::RuntimeConfig;

/// Factory: create the right runtime from config
pub fn create_runtime(config: &RuntimeConfig) -> anyhow::Result<Box<dyn RuntimeAdapter>> {
    match config.kind.as_str() {
        "native" => Ok(Box::new(NativeRuntime::new())),
        "docker" => Ok(Box::new(DockerRuntime::new(config.docker.clone()))),
        "wasm" => {
            #[cfg(feature = "runtime-wasm")]
            {
                Ok(Box::new(WasmRuntime::new(config.wasm.clone())))
            }

            #[cfg(not(feature = "runtime-wasm"))]
            {
                anyhow::bail!(
                    "runtime.kind='wasm' requires the `runtime-wasm` feature. Rebuild with `cargo build --features runtime-wasm`."
                )
            }
        }
        "cloudflare" => anyhow::bail!(
            "runtime.kind='cloudflare' is not implemented yet. Use runtime.kind='native' for now."
        ),
        other if other.trim().is_empty() => {
            anyhow::bail!("runtime.kind cannot be empty. Supported values: native, docker, wasm")
        }
        other => {
            anyhow::bail!("Unknown runtime kind '{other}'. Supported values: native, docker, wasm")
        }
    }
}

/// Resolve the capability contract for the configured runtime.
pub fn runtime_capabilities(config: &RuntimeConfig) -> anyhow::Result<RuntimeCapabilities> {
    Ok(create_runtime(config)?.capabilities())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn factory_native() {
        let cfg = RuntimeConfig {
            kind: "native".into(),
            ..RuntimeConfig::default()
        };
        let rt = create_runtime(&cfg).unwrap();
        assert_eq!(rt.name(), "native");
        assert!(rt.has_shell_access());
    }

    #[test]
    fn capability_contract_native() {
        let cfg = RuntimeConfig {
            kind: "native".into(),
            ..RuntimeConfig::default()
        };

        let capabilities = runtime_capabilities(&cfg).unwrap();
        assert_eq!(capabilities, RuntimeCapabilities::new(true, true, true, 0));
    }

    #[test]
    fn factory_docker() {
        let cfg = RuntimeConfig {
            kind: "docker".into(),
            ..RuntimeConfig::default()
        };
        let rt = create_runtime(&cfg).unwrap();
        assert_eq!(rt.name(), "docker");
        assert!(rt.has_shell_access());
    }

    #[cfg(feature = "runtime-wasm")]
    #[test]
    fn factory_wasm() {
        let cfg = RuntimeConfig {
            kind: "wasm".into(),
            ..RuntimeConfig::default()
        };
        let rt = create_runtime(&cfg).unwrap();
        assert_eq!(rt.name(), "wasm");
        assert!(!rt.has_shell_access());
    }

    #[cfg(not(feature = "runtime-wasm"))]
    #[test]
    fn factory_wasm_requires_feature() {
        let cfg = RuntimeConfig {
            kind: "wasm".into(),
            ..RuntimeConfig::default()
        };
        match create_runtime(&cfg) {
            Err(err) => assert!(err.to_string().contains("runtime-wasm")),
            Ok(_) => panic!("wasm runtime should require the runtime-wasm feature"),
        }
    }

    #[test]
    fn factory_cloudflare_errors() {
        let cfg = RuntimeConfig {
            kind: "cloudflare".into(),
            ..RuntimeConfig::default()
        };
        match create_runtime(&cfg) {
            Err(err) => assert!(err.to_string().contains("not implemented")),
            Ok(_) => panic!("cloudflare runtime should error"),
        }
    }

    #[test]
    fn factory_unknown_errors() {
        let cfg = RuntimeConfig {
            kind: "wasm-edge-unknown".into(),
            ..RuntimeConfig::default()
        };
        match create_runtime(&cfg) {
            Err(err) => assert!(err.to_string().contains("Unknown runtime kind")),
            Ok(_) => panic!("unknown runtime should error"),
        }
    }

    #[test]
    fn factory_empty_errors() {
        let cfg = RuntimeConfig {
            kind: String::new(),
            ..RuntimeConfig::default()
        };
        match create_runtime(&cfg) {
            Err(err) => assert!(err.to_string().contains("cannot be empty")),
            Ok(_) => panic!("empty runtime should error"),
        }
    }
}
