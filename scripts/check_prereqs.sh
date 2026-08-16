#!/usr/bin/env bash
# Fail fast if GitHub Actions secrets / env prerequisites are missing.
set -euo pipefail

missing=()
require() {
  local name="$1"
  local value="${!name-}"
  if [[ -z "${value}" ]]; then
    missing+=("$name")
  fi
}

echo "Checking Watchpost deploy prerequisites..."
echo

require AWS_ACCESS_KEY_ID
require AWS_SECRET_ACCESS_KEY
require SSH_PRIVATE_KEY
require SSH_PUBLIC_KEY
require OPENROUTER_API_KEY
require TELEGRAM_BOT_TOKEN
require TELEGRAM_CHAT_ID
require CANARY_AWS_ACCESS_KEY_ID
require CANARY_AWS_SECRET_ACCESS_KEY

if [[ -n "${CANARY_AWS_ACCESS_KEY_ID:-}" && "${CANARY_AWS_ACCESS_KEY_ID}" != AKIA* ]]; then
  echo "WARN: CANARY_AWS_ACCESS_KEY_ID does not start with AKIA (unexpected for AWS-key Canarytokens)."
fi
if [[ -n "${SSH_PUBLIC_KEY:-}" && "${SSH_PUBLIC_KEY}" != ssh-* ]]; then
  echo "WARN: SSH_PUBLIC_KEY does not look like an OpenSSH public key (ssh-ed25519 / ssh-rsa)."
fi
if [[ -n "${TELEGRAM_BOT_TOKEN:-}" && "${TELEGRAM_BOT_TOKEN}" != *:* ]]; then
  echo "WARN: TELEGRAM_BOT_TOKEN usually looks like 123456:ABC-DEF..."
fi

if ((${#missing[@]} > 0)); then
  echo
  echo "ERROR: missing required GitHub Actions secrets / env vars:"
  for m in "${missing[@]}"; do
    printf '  - %s\n' "$m"
  done
  cat <<'EOF'

Set them under: Repository → Settings → Secrets and variables → Actions

Required secrets
  AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY
      Real IAM user/role keys that can create VPC + EC2 (NOT Canary keys).
  SSH_PRIVATE_KEY / SSH_PUBLIC_KEY
      Key pair used for admin SSH on port 2222.
  OPENROUTER_API_KEY
      OpenRouter key for the Beelzebub LLM catch-all.
  TELEGRAM_BOT_TOKEN / TELEGRAM_CHAT_ID
      BotFather token + destination chat id for alerts.
  CANARY_AWS_ACCESS_KEY_ID / CANARY_AWS_SECRET_ACCESS_KEY
      Thinkst Canarytoken AWS keys (tripwire only — not real IAM).

Optional secrets / workflow inputs
  CANARY_AWS_REGION   (default us-east-2)
  AWS_REGION           (default eu-west-2)
  INSTANCE_TYPE        (default m7i-flex.large)
  LLM_MODEL            (default openai/gpt-4.1-nano)
  ADMIN_CIDR           (default 0.0.0.0/0 — lock this down for real use)

Create a Canary AWS-keys token at https://canarytokens.org/generate
Create a Telegram bot via @BotFather, then message it and resolve chat id.
EOF
  exit 1
fi

echo "All required secrets are present."
echo "Optional: CANARY_AWS_REGION=${CANARY_AWS_REGION:-us-east-2}"
echo "Optional: AWS_REGION=${AWS_REGION:-eu-west-2}"
echo "Optional: INSTANCE_TYPE=${INSTANCE_TYPE:-m7i-flex.large}"
echo "Optional: LLM_MODEL=${LLM_MODEL:-openai/gpt-4.1-nano}"
echo "Optional: ADMIN_CIDR=${ADMIN_CIDR:-0.0.0.0/0}"
echo "Prerequisite check passed."
