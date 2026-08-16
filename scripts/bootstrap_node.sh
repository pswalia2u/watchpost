#!/usr/bin/env bash
# Inject secrets into Beelzebub configs and bootstrap the Watchpost node over SSH.
set -euo pipefail

PUBLIC_IP="${PUBLIC_IP:?PUBLIC_IP is required}"
SSH_KEY_FILE="${SSH_KEY_FILE:?SSH_KEY_FILE is required}"
OPENROUTER_API_KEY="${OPENROUTER_API_KEY:?OPENROUTER_API_KEY is required}"
TELEGRAM_BOT_TOKEN="${TELEGRAM_BOT_TOKEN:?TELEGRAM_BOT_TOKEN is required}"
TELEGRAM_CHAT_ID="${TELEGRAM_CHAT_ID:?TELEGRAM_CHAT_ID is required}"
CANARY_AWS_ACCESS_KEY_ID="${CANARY_AWS_ACCESS_KEY_ID:?CANARY_AWS_ACCESS_KEY_ID is required}"
CANARY_AWS_SECRET_ACCESS_KEY="${CANARY_AWS_SECRET_ACCESS_KEY:?CANARY_AWS_SECRET_ACCESS_KEY is required}"
CANARY_AWS_REGION="${CANARY_AWS_REGION:-us-east-2}"
LLM_MODEL="${LLM_MODEL:-openai/gpt-4.1-nano}"
SSH_PORT="${SSH_PORT:-2222}"
SSH_USER="${SSH_USER:-ubuntu}"
REPO_ROOT="${REPO_ROOT:-$(cd "$(dirname "$0")/.." && pwd)}"

SSH=(ssh -i "$SSH_KEY_FILE" -p "$SSH_PORT"
  -o StrictHostKeyChecking=accept-new
  -o UserKnownHostsFile=/tmp/watchpost_known_hosts
  -o ConnectTimeout=15
  "${SSH_USER}@${PUBLIC_IP}")

SCP=(scp -i "$SSH_KEY_FILE" -P "$SSH_PORT"
  -o StrictHostKeyChecking=accept-new
  -o UserKnownHostsFile=/tmp/watchpost_known_hosts)

echo "==> Waiting for admin SSH on ${PUBLIC_IP}:${SSH_PORT}"
for i in $(seq 1 60); do
  if "${SSH[@]}" "test -x /usr/bin/docker && echo ready" 2>/dev/null | grep -q ready; then
    echo "SSH + Docker ready"
    break
  fi
  if [[ "$i" -eq 60 ]]; then
    echo "ERROR: timed out waiting for SSH/Docker on ${PUBLIC_IP}:${SSH_PORT}" >&2
    exit 1
  fi
  sleep 10
done

WORKDIR="$(mktemp -d)"
trap 'rm -rf "$WORKDIR"' EXIT
cp -a "${REPO_ROOT}/beelzebub/." "${WORKDIR}/beelzebub/"
mkdir -p "${WORKDIR}/deploy" "${WORKDIR}/secrets"
cp -a "${REPO_ROOT}/deploy/systemd/." "${WORKDIR}/deploy/"

python3 - <<PY
from pathlib import Path
root = Path(r"${WORKDIR}/beelzebub/configurations/services")
replacements = {
    "REPLACE_WITH_OPENROUTER_KEY": """${OPENROUTER_API_KEY}""",
    "REPLACE_WITH_PUBLIC_IP": """${PUBLIC_IP}""",
    "REPLACE_WITH_CANARY_AWS_ACCESS_KEY_ID": """${CANARY_AWS_ACCESS_KEY_ID}""",
    "REPLACE_WITH_CANARY_AWS_SECRET_ACCESS_KEY": """${CANARY_AWS_SECRET_ACCESS_KEY}""",
    "REPLACE_WITH_CANARY_AWS_REGION": """${CANARY_AWS_REGION}""",
    "openai/gpt-4.1-nano": """${LLM_MODEL}""",
}
for path in root.glob("*.yaml"):
    text = path.read_text(encoding="utf-8")
    for old, new in replacements.items():
        text = text.replace(old, new)
    path.write_text(text, encoding="utf-8")
    if "REPLACE_WITH_" in text:
        raise SystemExit(f"unresolved placeholder remains in {path}")
print("configs rendered")
PY

[[ "$CANARY_AWS_ACCESS_KEY_ID" == AKIA* ]] || echo "WARN: Canary access key usually starts with AKIA"
[[ "${#CANARY_AWS_SECRET_ACCESS_KEY}" -ge 20 ]] || { echo "ERROR: Canary secret looks too short"; exit 1; }

# Write telegram env locally then scp (avoids shell-escaping token quirks)
python3 - <<PY
from pathlib import Path
Path(r"${WORKDIR}/secrets/telegram.env").write_text(
    "TELEGRAM_BOT_TOKEN=${TELEGRAM_BOT_TOKEN}\n"
    "TELEGRAM_CHAT_ID=${TELEGRAM_CHAT_ID}\n",
    encoding="utf-8",
)
PY
chmod 600 "${WORKDIR}/secrets/telegram.env"

echo "==> Uploading Watchpost payload"
"${SSH[@]}" "mkdir -p /home/ubuntu/beelzebub/secrets /home/ubuntu/beelzebub/data /home/ubuntu/demo"
"${SCP[@]}" -r "${WORKDIR}/beelzebub/configurations" "${WORKDIR}/beelzebub/docker-compose.yml" \
  "${WORKDIR}/beelzebub/intel" "${SSH_USER}@${PUBLIC_IP}:/home/ubuntu/beelzebub/"
"${SCP[@]}" "${WORKDIR}/secrets/telegram.env" "${SSH_USER}@${PUBLIC_IP}:/home/ubuntu/beelzebub/secrets/telegram.env"
"${SCP[@]}" -r "${WORKDIR}/deploy" "${SSH_USER}@${PUBLIC_IP}:/tmp/watchpost-deploy"
if [[ -d "${REPO_ROOT}/demo" ]]; then
  "${SCP[@]}" -r "${REPO_ROOT}/demo/." "${SSH_USER}@${PUBLIC_IP}:/home/ubuntu/demo/" || true
fi

echo "==> Enabling services"
"${SSH[@]}" "bash -s" <<'REMOTE'
set -euo pipefail
chmod 600 /home/ubuntu/beelzebub/secrets/telegram.env
chown -R ubuntu:ubuntu /home/ubuntu/beelzebub

sudo cp /tmp/watchpost-deploy/systemd/canary-webhook.service /etc/systemd/system/canary-webhook.service
sudo cp /tmp/watchpost-deploy/systemd/tor-gateway.service /etc/systemd/system/tor-gateway.service
sudo systemctl daemon-reload

cd /home/ubuntu/beelzebub
sudo docker compose pull
sudo docker compose up -d

for i in $(seq 1 30); do
  if curl -fsS http://127.0.0.1:9080/health >/dev/null 2>&1; then
    break
  fi
  sleep 2
done

sudo systemctl enable --now canary-webhook.service tor-gateway.service
sudo systemctl restart canary-webhook.service tor-gateway.service
sudo systemctl --no-pager --lines=0 status canary-webhook.service tor-gateway.service || true
docker ps --format 'table {{.Names}}\t{{.Status}}\t{{.Ports}}'
REMOTE

echo "==> Smoke checks"
curl -fsS --max-time 15 "http://${PUBLIC_IP}/health" | head -c 200
echo
curl -fsS --max-time 15 "http://${PUBLIC_IP}/.env" | head -n 5
echo

cat <<EOF

========================================
Watchpost deployed
  Decoy API:        http://${PUBLIC_IP}
  Canary webhook:  http://${PUBLIC_IP}:8080/hook/canary
  Admin SSH:       ssh -i <key> -p ${SSH_PORT} ${SSH_USER}@${PUBLIC_IP}

Next:
  1. In Canarytokens.org, set the token webhook to:
     http://${PUBLIC_IP}:8080/hook/canary
  2. Point your public lure .env at the Canary keys you just deployed
  3. Demo: API=http://${PUBLIC_IP} ./demo/attack.sh
========================================
EOF
