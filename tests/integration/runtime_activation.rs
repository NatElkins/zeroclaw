use zeroclaw::config::Config;
use zeroclaw::runtime::create_runtime;

#[cfg(feature = "runtime-wasm")]
#[test]
fn runtime_kind_wasm_activation_smoke() {
    let mut cfg = Config::default();
    cfg.runtime.kind = "wasm".to_string();

    let runtime = create_runtime(&cfg.runtime).expect("runtime.kind=wasm should initialize");
    let capabilities = runtime.capabilities();

    assert_eq!(runtime.name(), "wasm");
    assert!(!capabilities.shell_access);
    assert!(!capabilities.filesystem_access);
    assert!(!capabilities.long_running);
}

#[cfg(feature = "runtime-wasm")]
#[test]
fn runtime_kind_wasm_activation_respects_filesystem_flags() {
    let mut cfg = Config::default();
    cfg.runtime.kind = "wasm".to_string();
    cfg.runtime.wasm.allow_workspace_read = true;

    let runtime = create_runtime(&cfg.runtime).expect("runtime.kind=wasm should initialize");
    let capabilities = runtime.capabilities();

    assert_eq!(runtime.name(), "wasm");
    assert!(!capabilities.shell_access);
    assert!(capabilities.filesystem_access);
    assert!(!capabilities.long_running);
}

#[cfg(not(feature = "runtime-wasm"))]
#[test]
fn runtime_kind_wasm_requires_runtime_wasm_feature() {
    let mut cfg = Config::default();
    cfg.runtime.kind = "wasm".to_string();

    match create_runtime(&cfg.runtime) {
        Ok(_) => panic!("runtime.kind=wasm should fail when runtime-wasm is disabled"),
        Err(err) => {
            let message = err.to_string();
            assert!(message.contains("runtime-wasm"));
            assert!(message.contains("runtime.kind='wasm'"));
        }
    }
}
