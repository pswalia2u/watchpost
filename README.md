# Watchpost

**AI-driven deception and early warning for cyber-poor aid and emergency operators.**

Watchpost is a solo, one-day hackathon project. It deploys a single lightweight cloud node that *looks* like a production humanitarian logistics and CI control-plane API. Automated attackers who scrape “leaked” cloud keys or probe the API get stuck in synthetic responses; defenders get scored alerts on Telegram within seconds—with IP geolocation, public threat intel, and Tor detection.

> **Source:** https://github.com/pswalia2u/watchpost  
> **Public lure (intentional Canarytoken `.env`):** https://github.com/pswalia2u/hlp-logistics-control-plane  
> **Deploy / destroy:** GitHub Actions — see [DEPLOY.md](DEPLOY.md)  
> **Example decoy API (prior demo node):** http://18.171.222.41

Nothing behind the decoy is real. There is no real warehouse database, no real IAM in the operator’s AWS account, and no beneficiary PII.

---

## Problem

Frontline humanitarian and emergency teams increasingly depend on digital logistics, cloud credentials, and public repositories. They rarely have a security operations centre.

Evidence that shaped this build:

| Finding | Source |
|---|---|
| ~241% rise in attacks on at-risk civil-society groups (12 months) | [Dark Reading / Cloudflare Project Galileo](https://www.darkreading.com/cyberattacks-data-breaches/attacks-humanitarian-orgs-jump-worldwide) · [NetHope 2025 report](https://nethope.org/toolkits/2025-state-of-humanitarian-and-development-cybersecurity-report/) |
| Nonprofits ranked highly as nation-state targets | [NetHope citing Microsoft Digital Defense Report 2024](https://nethope.org/toolkits/2025-state-of-humanitarian-and-development-cybersecurity-report/) |
| Many NGOs lack basics (training, monitoring, cyber plans) | [ReliefWeb / CyberPeace Institute](https://reliefweb.int/report/world/cyberattacks-real-threat-ngos-and-nonprofits) |
| Stolen credentials remain a leading breach pattern | [Verizon DBIR 2024](https://www.verizon.com/business/resources/reports/dbir/) |
| Leaked cloud keys on GitHub can be abused in ~127 seconds | [Cybenari / ThreatDown](https://www.threatdown.com/blog/you-have-one-minute-to-save-your-leaked-aws-credentials/) |
| Commodity campaigns steal thousands of cloud credentials | [Sysdig EMERALDWHALE](https://www.sysdig.com/blog/emeraldwhale) |
| Humanitarian data breaches have human cost | [ICRC 2022 cyber attack](https://www.icrc.org/en/document/cyber-attack-icrc-what-we-know) |

Watchpost does not replace patching or MFA. It gives understaffed teams a **cheap, phone-first early warning** when automated recon starts treating them like a target.

---

## Solution in one paragraph

I provision an AWS VM, run [Beelzebub](https://github.com/beelzebub-labs/beelzebub) as a fake **HLP Logistics Control Plane** API, connect unimplemented paths to an LLM via OpenRouter, plant Thinkst Canarytoken AWS keys in a public lure and on `/.env`, and stream events to a Python receiver that scores them (CVSS 4.0-style) and pushes Telegram alerts enriched with geo (ip-api), GreyNoise community intel, and Tor exit detection. Confirmed Tor exits hitting port 80 receive HTTP 403 `ANON_NETWORK_BLOCKED`, encouraging use of a direct IP for auditability.

---

## Architecture

```text
                    Internet scanners / curious attackers
                              |
         +--------------------+--------------------+
         |                    |                    |
   Public GitHub lure    Port 80 (API)        Port 22 (SSH decoy)
   (Canary .env)         Tor gateway            Beelzebub SSH
         |                    |                    |
         |                    v                    |
         |            Tor exit? --yes--> 403 JSON  |
         |                    | no                 |
         |                    v                    |
         |            Beelzebub :9080              |
         |         (static JSON + LLM)             |
         |                    |                    |
         |                    +----------+----------+
         |                               |
         v                               v
   Canarytokens.org              beelzebub.log (NDJSON)
         |                               |
         +----------> :8080 receiver <---+
                         |
                         +--> Telegram (geo / GreyNoise / Tor)
                         +--> data/intel/ extracts (files, no DB)
```

### Port map

| Port | Role |
|---|---|
| **80** | Public API via Tor policy gateway → Beelzebub |
| **22** | Decoy SSH (Beelzebub LLM terminal) — not Ubuntu |
| **2222** | Real admin SSH (`ubuntu`) |
| **8080** | Webhook receiver (Canary + policy + Beelzebub hooks) |
| **9080** | Beelzebub HTTP (localhost only) |
| **2112** | Prometheus metrics (localhost only) |

---

## Features

### 1. High-fidelity logistics API decoy

Static routes (instant, scripted):

- `GET /` — service catalogue, “degraded” auth gateway story  
- `GET /health` — fake dependency checks  
- `GET /v1/shipments` — fake aid shipments  
- `GET /v1/auth/token` — fake JWT  
- `GET /v1/ci/secrets` and `GET /.env` — intentional Canarytoken cloud keys  
- `GET /v1/openapi.json` — fake OpenAPI stub  

Catch-all (`^.*$`): **LLMHoneypot** via OpenRouter (`openai/gpt-4.1-nano`). The model is prompted to answer *only* as the logistics API in JSON—no shell, no “I am an AI.”

### 2. Public lure + Canary tripwire

- Lure repo: https://github.com/pswalia2u/hlp-logistics-control-plane  
- Keys are **Thinkst Canarytokens**, not real operator IAM.  
- Using the keys against AWS STS triggers email + webhook → Telegram **CRITICAL**.

### 3. Scored phone alerts

Every Beelzebub HTTP/SSH event and Canary hit becomes a Telegram message with:

- Severity + CVSS 4.0-style vector string (heuristic mapping, not a NIST calculator)  
- Source IP, activity path / command, user-agent  
- **Geo** (city / region / country)  
- **ISP / ASN**  
- **Known malicious?** (GreyNoise community)  
- **VPN/Proxy/Tor** signal (Tor exit list = high confidence; ISP heuristics = lower confidence)

### 4. Tor policy gate (HLP-SEC-ANON-01)

Only **confirmed Tor exits** are blocked (high confidence). Heuristic “likely VPN/hosting” (e.g. Datacamp) is reported on alerts but **not** blocked.

Tor clients receive:

```json
{
  "error": "access_denied",
  "code": "ANON_NETWORK_BLOCKED",
  "message": "Tor, VPN, and proxy access is not permitted on the HLP Logistics Control Plane. Connect from a direct (non-anonymised) network and retry.",
  "policy": "HLP-SEC-ANON-01"
}
```

### 5. File-based threat intel store

No SQLite/Postgres. On the VM under `/home/ubuntu/beelzebub/data/`:

| File | Contents |
|---|---|
| `beelzebub.log` | Master NDJSON event stream |
| `intel/summary.json` | Counts, unique IPs, event types |
| `intel/events.jsonl`, `credentials.jsonl`, `commands.jsonl` | Parsed IOC extracts |
| `canary-events.jsonl` | Raw Canary webhooks |
| `telegram-alerts.jsonl` | Alert audit trail |

---

## Quick demo (60 seconds)

After deploy, replace `<PUBLIC_IP>` with your node (job summary prints it). Example below uses a prior demo host:

```bash
API="${API:-http://18.171.222.41}"   # or http://<PUBLIC_IP> from Deploy summary
curl -sS "$API/health" | python3 -m json.tool
curl -sS "$API/v1/shipments" | python3 -m json.tool | head
curl -sS "$API/.env"
curl -sS -m 20 "$API/v1/admin/jobs"   # LLM catch-all
```

Full assumed-breach script (recon → secrets → Canary STS → Tor probe → LLM tarpit):

```bash
API=http://<PUBLIC_IP> ./demo/attack.sh
```

Split-screen: attacker terminal on the left, Telegram alerts on the phone.

Admin SSH (operators only):

```bash
ssh -i ~/.ssh/id_ed25519 -p 2222 ubuntu@<PUBLIC_IP>
```

---

## Repository layout

```text
watchpost/
├── README.md
├── DEPLOY.md                     # Full deploy / destroy / secrets guide
├── .github/workflows/
│   ├── deploy.yml                 # Actions: Deploy Watchpost
│   └── destroy.yml                # Actions: Destroy Watchpost
├── iaac/                          # Terraform: VPC, SG, Ubuntu VM
│   ├── main.tf
│   ├── variables.tf
│   ├── versions.tf
│   └── terraform.tfvars.example
├── deploy/systemd/                # canary-webhook + tor-gateway units
├── scripts/
│   ├── check_prereqs.sh           # Fail-fast secret checklist
│   └── bootstrap_node.sh          # SSH inject secrets + start stack
├── beelzebub/
│   ├── docker-compose.yml         # Beelzebub on :22 and localhost:9080
│   ├── configurations/
│   │   ├── beelzebub.yaml
│   │   └── services/
│   │       ├── http-80.yaml       # Placeholders filled at bootstrap
│   │       └── ssh-22.yaml
│   └── intel/
│       ├── receiver.py           # Webhooks, CVSS, Telegram, CTI
│       ├── tor_gateway.py
│       └── extract_iocs.py
├── demo/
│   ├── attack.sh
│   └── PITCH.txt
└── lure/                          # Materials mirrored in the public lure repo
```

---

## Technology stack

| Layer | Technology |
|---|---|
| Cloud | AWS EC2, VPC, Security Groups (eu-west-2) |
| IaC | Terraform |
| CI/CD | GitHub Actions (`deploy.yml` / `destroy.yml`) |
| Deception | Beelzebub (`m4r10/beelzebub`) |
| LLM | OpenRouter → `openai/gpt-4.1-nano` |
| Tripwire | Thinkst Canarytokens (AWS keys) |
| Alerts | Telegram Bot API |
| Geo | http://ip-api.com |
| Scanner intel | GreyNoise community API |
| Tor | https://check.torproject.org/torbulkexitlist |
| Runtime glue | Python 3 (stdlib HTTP), systemd, Docker Compose |

I did **not** train a custom model. The “AI” is orchestration: a deception runtime plus a small paid LLM for adaptive JSON tarpitting.

---

## Deploy & destroy (GitHub Actions)

Full walkthrough: **[DEPLOY.md](DEPLOY.md)**.

### Required repository secrets

**Settings → Secrets and variables → Actions**

| Secret | Purpose |
|---|---|
| `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` | Real IAM that can create VPC + EC2 (**not** Canary keys) |
| `SSH_PRIVATE_KEY` / `SSH_PUBLIC_KEY` | Admin SSH on port **2222** |
| `OPENROUTER_API_KEY` | LLM tarpit (OpenRouter) |
| `TELEGRAM_BOT_TOKEN` / `TELEGRAM_CHAT_ID` | Phone alerts |
| `CANARY_AWS_ACCESS_KEY_ID` / `CANARY_AWS_SECRET_ACCESS_KEY` | Thinkst Canarytoken tripwire keys |

### Deploy

1. **Actions → Deploy Watchpost → Run workflow**
2. Tick **confirm_prerequisites** (required — otherwise the job fails with a checklist)
3. Optional inputs: `aws_region` (`eu-west-2`), `instance_type`, `llm_model`, `admin_cidr`, `canary_aws_region`
4. Workflow: validate secrets → `terraform apply` → SSH bootstrap (Beelzebub + Telegram + Tor gateway) → smoke checks
5. Job summary prints **decoy API** and **Canary webhook** URLs; Terraform state is uploaded as artifact `watchpost-terraform-state`

**After deploy**

1. Set the Canarytoken webhook to `http://<PUBLIC_IP>:8080/hook/canary`
2. Align the public lure `.env` with the same Canary keys
3. Demo: `API=http://<PUBLIC_IP> ./demo/attack.sh`

### Destroy

1. **Actions → Destroy Watchpost → Run workflow**
2. Tick **confirm_destroy** (required)
3. Use the **same** region / project / instance / CIDR as deploy
4. Leave `deploy_run_id` empty to use the latest successful Deploy state artifact (or paste a run id)
5. Secrets needed for destroy: `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `SSH_PUBLIC_KEY`

Destroys the EC2 node, VPC, subnet, IGW, security group, and key pair from that state.

### Manual (without Actions)

```bash
# Terraform (see iaac/terraform.tfvars.example)
cd iaac && terraform apply

# Bootstrap
export PUBLIC_IP=...
export SSH_KEY_FILE=~/.ssh/id_ed25519
export OPENROUTER_API_KEY=...
export TELEGRAM_BOT_TOKEN=...
export TELEGRAM_CHAT_ID=...
export CANARY_AWS_ACCESS_KEY_ID=...
export CANARY_AWS_SECRET_ACCESS_KEY=...
./scripts/bootstrap_node.sh
```

---

## Safety, legality, and responsible use

- **Decoy only.** No real aid shipments, no real beneficiary data, no real production IAM for the operator.  
- **Canary / synthetic credentials** for tripwires. Do not use them against anyone else’s systems.  
- `demo/attack.sh` must target **only** this decoy node and the Canarytoken.  
- Geo is **IP geolocation** (VPN/Tor exits show the exit’s location, not a home address).  
- “Known malicious” means **public scanner intel**, not a legal finding.  
- Tor block is a **policy demo** to push attackers off anonymity networks; only Tor exits are enforced with high confidence.  
- Public lure keys will be crawled by bots (noise). For a real pilot: private lure, SSH locked to operator IPs, alert throttling.

---

## What this is not

- Not a nation-state defence platform  
- Not a full CVSS 4.0 calculator (vectors are explainable heuristics)  
- Not a SIEM / ELK stack  
- Not a replacement for patching, MFA, or backups  

It is a **practical packaging** of AI deception + public CTI + mobile warning for people who protect communities under severe resource constraints.

---

## Author

Solo build for a one-day hackathon focused on practical technology that protects people and supports frontline operators.

---

## License

Hackathon demonstration code. Use responsibly. Do not deploy deception systems without clear rules of engagement and organisational approval.
