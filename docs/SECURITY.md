# Security checklist

| Requirement | Implementation |
|---|---|
| HTTPS | Terminate TLS at the cloud load balancer / Caddy / nginx (see DEPLOYMENT.md); HSTS header set by the API |
| Password hashing | PBKDF2-HMAC-SHA256, 240k iterations, per-user salt, constant-time compare |
| JWT / sessions | HS256 signed, expiry (`JWT_TTL_MINUTES`), secret from env; invalid/expired → 401 |
| API authentication | Bearer token on every scan/history/admin route; role check for admin |
| Input validation | Pydantic models: length limits, URL scheme allow-list, email regex, password rules |
| NoSQL/SQL injection | Typed Pydantic strings (operator objects such as `{"$ne": ""}` are rejected); parameterised driver queries; no string-built queries |
| XSS | React escapes output; user content is never injected as HTML; API sends CSP + nosniff headers; extension banner built with `textContent` |
| Rate limiting | Per-IP sliding window (auth 10/min, scans 30/min, default 240/min) |
| Secure file handling | Only `.eml/.txt`, 1 MB cap, parsed as text; attachments are **metadata only – never opened or executed** |
| No execution of submitted content | Server never renders pages or runs scripts; page inspection is a size-capped static read |
| SSRF protection | DNS resolved and every redirect hop checked: private/loopback/link-local/reserved targets are refused |
| Privacy | Admin views never show message/email content; users only see their own scans |
| Logging & monitoring | Structured request logs with request IDs, failed-login warnings, `/api/health`, admin system-status panel |
| Container hardening | Non-root user, slim image, healthcheck |

Known limits: DNS-rebinding TOCTOU remains possible for live checks – run the backend in an egress-restricted network segment in production. Rotate `JWT_SECRET` and change the default admin password before deployment.
