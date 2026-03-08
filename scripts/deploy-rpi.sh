#!/usr/bin/env bash
# deploy-rpi.sh — cross-compile ZeroClaw for Raspberry Pi and deploy via SSH.
#
# Requirements (macOS/Linux host):
#   cargo install cross   (Docker-based cross-compiler)
#   Docker running
#
# Usage:
#   RPI_HOST=raspberrypi.local RPI_USER=pi ./scripts/deploy-rpi.sh
#
# Optional env vars:
#   RPI_HOST   — hostname or IP of the Pi (default: raspberrypi.local)
#   RPI_USER   — SSH user on the Pi     (default: pi)
#   RPI_PORT   — SSH port               (default: 22)
#   RPI_DIR    — remote deployment dir  (default: /home/$RPI_USER/zeroclaw)

set -euo pipefail

RPI_HOST="${RPI_HOST:-raspberrypi.local}"
RPI_USER="${RPI_USER:-pi}"
RPI_PORT="${RPI_PORT:-22}"
RPI_DIR="${RPI_DIR:-/home/${RPI_USER}/zeroclaw}"
TARGET="aarch64-unknown-linux-gnu"
FEATURES="hardware,peripheral-rpi"
BINARY="target/${TARGET}/release/zeroclaw"
SSH_OPTS="-p ${RPI_PORT} -o StrictHostKeyChecking=no -o ConnectTimeout=10"

echo "==> Building ZeroClaw for Raspberry Pi (${TARGET})"
echo "    Features: ${FEATURES}"
echo "    Target host: ${RPI_USER}@${RPI_HOST}:${RPI_PORT}"
echo ""

# ── 1. Cross-compile ──────────────────────────────────────────────────────────
cross build \
  --target "${TARGET}" \
  --features "${FEATURES}" \
  --release

echo ""
echo "==> Build complete: ${BINARY}"
ls -lh "${BINARY}"

# ── 2. Create remote directory ────────────────────────────────────────────────
echo ""
echo "==> Creating remote directory ${RPI_DIR}"
# shellcheck disable=SC2029
ssh ${SSH_OPTS} "${RPI_USER}@${RPI_HOST}" "mkdir -p ${RPI_DIR}"

# ── 3. Deploy binary ──────────────────────────────────────────────────────────
echo ""
echo "==> Deploying binary to ${RPI_USER}@${RPI_HOST}:${RPI_DIR}/zeroclaw"
scp ${SSH_OPTS} "${BINARY}" "${RPI_USER}@${RPI_HOST}:${RPI_DIR}/zeroclaw"

# ── 4. Create .env skeleton (if it doesn't exist) ────────────────────────────
ENV_DEST="${RPI_DIR}/.env"
echo ""
echo "==> Checking for ${ENV_DEST}"
# shellcheck disable=SC2029
if ssh ${SSH_OPTS} "${RPI_USER}@${RPI_HOST}" "[ -f ${ENV_DEST} ]"; then
  echo "    .env already exists — skipping"
else
  echo "    Creating .env skeleton with 600 permissions"
  # shellcheck disable=SC2029
  ssh ${SSH_OPTS} "${RPI_USER}@${RPI_HOST}" \
    "mkdir -p ${RPI_DIR} && \
     printf '# Set your API key here\nANTHROPIC_API_KEY=sk-ant-\n' > ${ENV_DEST} && \
     chmod 600 ${ENV_DEST}"
  echo "    IMPORTANT: edit ${ENV_DEST} on the Pi and set ANTHROPIC_API_KEY"
fi

# ── 5. Deploy config (if it doesn't already exist remotely) ──────────────────
CONFIG_DEST="/home/${RPI_USER}/.zeroclaw/config.toml"
echo ""
echo "==> Checking for existing config at ${CONFIG_DEST}"
# shellcheck disable=SC2029
if ssh ${SSH_OPTS} "${RPI_USER}@${RPI_HOST}" "[ -f ${CONFIG_DEST} ]"; then
  echo "    Config already exists — skipping (edit manually if needed)"
else
  echo "    Deploying starter config to ${CONFIG_DEST}"
  # shellcheck disable=SC2029
  ssh ${SSH_OPTS} "${RPI_USER}@${RPI_HOST}" "mkdir -p /home/${RPI_USER}/.zeroclaw"
  scp ${SSH_OPTS} "scripts/rpi-config.toml" "${RPI_USER}@${RPI_HOST}:${CONFIG_DEST}"
fi

# ── 6. Deploy and enable systemd service ─────────────────────────────────────
SERVICE_DEST="/etc/systemd/system/zeroclaw.service"
echo ""
echo "==> Installing systemd service (requires sudo on the Pi)"
scp ${SSH_OPTS} "scripts/zeroclaw.service" "${RPI_USER}@${RPI_HOST}:/tmp/zeroclaw.service"
# shellcheck disable=SC2029
ssh ${SSH_OPTS} "${RPI_USER}@${RPI_HOST}" \
  "sudo mv /tmp/zeroclaw.service ${SERVICE_DEST} && \
   sudo systemctl daemon-reload && \
   sudo systemctl enable zeroclaw && \
   sudo systemctl restart zeroclaw && \
   sudo systemctl status zeroclaw --no-pager || true"

# ── 7. Runtime permissions ───────────────────────────────────────────────────
echo ""
echo "==> Granting ${RPI_USER} access to GPIO group"
# shellcheck disable=SC2029
ssh ${SSH_OPTS} "${RPI_USER}@${RPI_HOST}" \
  "sudo usermod -aG gpio ${RPI_USER} || true"

# ── 8. Reset ACT LED trigger so ZeroClaw can control it ──────────────────────
echo ""
echo "==> Resetting ACT LED trigger (none)"
# shellcheck disable=SC2029
ssh ${SSH_OPTS} "${RPI_USER}@${RPI_HOST}" \
  "echo none | sudo tee /sys/class/leds/ACT/trigger > /dev/null 2>&1 || true"

echo ""
echo "==> Deployment complete!"
echo ""
echo "    ZeroClaw is running at http://${RPI_HOST}:8080"
echo "    POST /api/chat  — chat with the agent"
echo "    GET  /health    — health check"
echo ""
echo "    To check logs: ssh ${RPI_USER}@${RPI_HOST} 'journalctl -u zeroclaw -f'"
