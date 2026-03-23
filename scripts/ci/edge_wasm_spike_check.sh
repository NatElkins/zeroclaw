#!/usr/bin/env bash
set -euo pipefail

# Ensure wasm target exists when rustup is available. Some environments (e.g. Nix)
# provide cargo/rustc outside rustup; in that case we still run checks directly.
if command -v rustup >/dev/null 2>&1; then
  toolchain="${EDGE_SPIKE_TOOLCHAIN:-stable}"
  rustup target add --toolchain "${toolchain}" wasm32-unknown-unknown

  # Keep cargo/rustc/rustdoc on one toolchain to avoid metadata-version mismatches.
  export RUSTC="$(rustup which --toolchain "${toolchain}" rustc)"
  export RUSTDOC="$(rustup which --toolchain "${toolchain}" rustdoc)"
  cargo_cmd=(rustup run "${toolchain}" cargo)
else
  cargo_cmd=(cargo)
fi

"${cargo_cmd[@]}" test -p zeroclaw-edge --locked --verbose
"${cargo_cmd[@]}" check -p zeroclaw-edge --target wasm32-unknown-unknown --locked --verbose
