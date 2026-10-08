# Cloud deployment

## 1. Database – MongoDB Atlas
Create a free M0 cluster → Database Access user → Network Access (allow your cloud egress IP) → copy the connection string into `MONGODB_URI`.

## 2. Backend + frontend containers
```bash
docker compose build
docker tag <image> <registry>/cybershield-backend:1.0   # push to ECR / ACR / Artifact Registry
```
| Cloud | Simplest managed path |
|---|---|
| AWS | ECR → App Runner or ECS Fargate behind an ALB (ACM certificate for HTTPS); secrets in Secrets Manager |
| Azure | ACR → Azure Container Apps (managed HTTPS); secrets in Key Vault |
| Google Cloud | Artifact Registry → Cloud Run (managed HTTPS); secrets in Secret Manager |

Set the env vars from `.env.example` as service secrets. Expose the **frontend** container (nginx proxies `/api` to the backend), or deploy the backend separately and set `CORS_ORIGINS` to the frontend origin.

## 3. Single VM option
Ubuntu VM + Docker + Caddy: `your-domain.com { reverse_proxy localhost:8080 }` gives automatic Let's Encrypt HTTPS.

## 4. Monitoring
Ship container stdout (JSON logs) to CloudWatch / Azure Monitor / Cloud Logging; alert on 5xx rate and `/api/health` failures.
