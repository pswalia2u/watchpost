# HLP Logistics Control Plane

Internal CI helpers for the humanitarian logistics API (prod).

**API:** http://18.171.222.41  
**Region:** us-east-2  
**Owner:** SRE / hlp-ops

## Quick start

```bash
cp .env.example .env   # or use the checked-in .env for prod CI
aws configure --profile hlp-prod
make shipments
```

Do not rotate the prod IAM user `hlp-logistics-prod-admin` without paging on-call.

## Endpoints

- `GET /health`
- `GET /v1/shipments`
- `GET /v1/ci/secrets`
- `POST /v1/auth/token`
- `GET /v1/admin/jobs`
