# Deploy Watchpost

GitHub Actions workflow: **Actions → Deploy Watchpost → Run workflow**.

## 1. Create repository secrets

**Settings → Secrets and variables → Actions → New repository secret**

| Secret | What it is |
|---|---|
| `AWS_ACCESS_KEY_ID` | Real IAM keys that can create VPC + EC2 (**not** Canary) |
| `AWS_SECRET_ACCESS_KEY` | Matching secret |
| `SSH_PRIVATE_KEY` | Admin private key (ed25519 recommended) |
| `SSH_PUBLIC_KEY` | Matching `.pub` line (`ssh-ed25519 AAAA…`) |
| `OPENROUTER_API_KEY` | From [OpenRouter](https://openrouter.ai/keys) |
| `TELEGRAM_BOT_TOKEN` | From [@BotFather](https://t.me/BotFather) |
| `TELEGRAM_CHAT_ID` | Chat/channel id that should receive alerts |
| `CANARY_AWS_ACCESS_KEY_ID` | Thinkst Canarytoken access key (`AKIA…`) |
| `CANARY_AWS_SECRET_ACCESS_KEY` | Matching Canary secret |

### Generate helpers

```bash
# SSH keypair for admin port 2222
ssh-keygen -t ed25519 -f watchpost -N ""
# Paste watchpost → SSH_PRIVATE_KEY, watchpost.pub → SSH_PUBLIC_KEY

# Telegram chat id (message the bot first)
curl -sS "https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/getUpdates" | python3 -m json.tool
```

Canary AWS-keys token: https://canarytokens.org/generate

## 2. Run the workflow

1. Open **Actions → Deploy Watchpost**.
2. Tick **confirm_prerequisites** (required — otherwise the job fails with a checklist).
3. Optionally set region / instance type / LLM model / admin CIDR.
4. Click **Run workflow**.

The workflow will:

1. Validate every required secret is present (fails early with a clear list if not).
2. `terraform apply` the VPC + Ubuntu node (`iaac/`).
3. SSH in on **2222**, inject OpenRouter + Canary keys into Beelzebub YAML, write Telegram env, start Docker + systemd (`canary-webhook`, `tor-gateway`).
4. Print decoy API + Canary webhook URLs in the job summary.
5. Upload `terraform.tfstate` as an artifact (keep it if you need a later destroy).

## 3. After deploy

1. Set the Canarytoken **webhook** to `http://<public-ip>:8080/hook/canary`.
2. Align your public lure `.env` with the same Canary keys.
3. Smoke test:

```bash
curl -sS http://<public-ip>/health
curl -sS http://<public-ip>/.env
API=http://<public-ip> ./demo/attack.sh
```

## Local bootstrap (without Actions)

```bash
# after terraform apply with ssh_public_key set
export PUBLIC_IP=...
export SSH_KEY_FILE=~/.ssh/watchpost
export OPENROUTER_API_KEY=...
export TELEGRAM_BOT_TOKEN=...
export TELEGRAM_CHAT_ID=...
export CANARY_AWS_ACCESS_KEY_ID=...
export CANARY_AWS_SECRET_ACCESS_KEY=...
./scripts/check_prereqs.sh   # needs the AWS_* + SSH_* vars too if you use it
./scripts/bootstrap_node.sh
```

## 4. Destroy

**Actions → Destroy Watchpost → Run workflow**

1. Tick **confirm_destroy** (required).
2. Use the **same** `aws_region` / `project_name` / `instance_type` / `admin_cidr` as deploy.
3. Leave `deploy_run_id` empty to use the latest successful Deploy artifact, or paste a specific run id.
4. Required secrets for destroy only: `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `SSH_PUBLIC_KEY`.

The workflow downloads the `watchpost-terraform-state` artifact from Deploy, then runs `terraform destroy`.

## Safety

- Canary keys are **tripwires**, not operator IAM.
- Lock `admin_cidr` to your IP `/32` for anything beyond a short demo.
- Decoy only — no real beneficiary data.
