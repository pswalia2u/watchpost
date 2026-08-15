# Watchpost

Solo one-day hackathon build: a **lightweight AI deception + early-warning node** for aid / emergency operators who cannot run a SOC.

Live decoy API: http://18.171.222.41  
Public lure (intentional Canarytoken `.env`): https://github.com/pswalia2u/hlp-logistics-control-plane

## What it does

1. Impersonates a humanitarian logistics / CI control-plane API (Beelzebub).
2. Serves static JSON for “real” endpoints; unimplemented paths are answered by an LLM (OpenRouter) as synthetic API JSON.
3. Plants Canarytoken AWS keys in `/.env` and a public GitHub lure.
4. Webhook receiver scores events (CVSS 4.0-style) and alerts Telegram with geo, GreyNoise, and Tor/VPN hints.
5. Confirmed **Tor exits** are blocked on port 80 with `ANON_NETWORK_BLOCKED` (policy HLP-SEC-ANON-01) so attackers are pushed to use a direct IP.

## Quick demo

```bash
curl -sS http://18.171.222.41/health
curl -sS http://18.171.222.41/v1/shipments
curl -sS http://18.171.222.41/.env
curl -sS -m 20 http://18.171.222.41/v1/admin/jobs
./demo/attack.sh
```

## Repo layout

| Path | Purpose |
|---|---|
| `iaac/` | Terraform (AWS VPC + VM + SG) |
| `beelzebub/` | Docker Compose, YAML honeypot configs, intel/receiver, Tor gateway |
| `demo/` | Assumed-breach script + pitch notes |
| `lure/` | Copy of the public GitHub lure materials |

## Secrets (not in git)

Copy placeholders before deploy:

- `beelzebub/configurations/services/*.yaml` → `openAISecretKey`
- VM only: `/home/ubuntu/beelzebub/secrets/telegram.env` (`TELEGRAM_BOT_TOKEN`, `TELEGRAM_CHAT_ID`)

## Safety

Decoy only. No real beneficiary data. Canary / synthetic credentials. Do not point `demo/attack.sh` at third-party systems.

## License

Hackathon demo code — use responsibly.
