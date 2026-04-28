# Veeam Recovery Agent

New Relic APM alert → Veeam Instant VM Recovery bridge.

Receives a New Relic webhook, scores available restore points for the affected VM
using a confidence algorithm, and waits for operator confirmation before triggering
an Instant VM Recovery via the Veeam B&R REST API (v1.3-rev1).

---

## Architecture

```
New Relic Alert (ACTIVATED)
  └─► POST /webhook/newrelic
        ├─ Fetches last 10 restore points (GET /api/v1/restorePoints)
        ├─ Enriches with repository info  (GET /api/v1/backups/{id})
        ├─ Scores each eligible point → selects highest-scoring
        └─ Returns confirmation token + confidence breakdown (TTL: 30 min)

Operator: GET  /confirm/{token}   ← review restore point + confidence details
Operator: POST /confirm/{token}   ← approve or reject

  approved ──► Veeam Instant VM Recovery  ──► NR Custom Event: RecoveryStarted
  rejected ──────────────────────────────────► NR Custom Event: RecoveryRejected
```

Restored VM is named `{original-hostname}-NewRelic`.

> **NR Ingest note:** Only Custom Events (a few bytes per recovery action) are sent
> to New Relic. Container logs stay on `stdout` and are never forwarded to NR unless
> you explicitly set up log shipping.

---

## Setup

### 1. Configure environment

```bash
cp .env.example .env
```

Edit `.env`:

```env
VEEAM_URL=https://veeam.corp.local:9419
VEEAM_USERNAME=svc-recovery
VEEAM_PASSWORD=changeme

NR_ACCOUNT_ID=your-account-id
NR_LICENSE_KEY=your-ingest-license-key
```

### 2. Start the container

```bash
docker network create monitoring   # only once
docker-compose up -d
```

Check it's running:

```bash
curl http://localhost:8000/health
```

---

## Configuration reference

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `VEEAM_URL` | Yes | — | Veeam B&R server URL, e.g. `https://veeam.corp.local:9419` |
| `VEEAM_USERNAME` | Yes | — | |
| `VEEAM_PASSWORD` | Yes | — | |
| `VEEAM_VERIFY_SSL` | No | `true` | Set `false` to skip TLS verification |
| `VEEAM_API_VERSION` | No | `1.3-rev1` | |
| `NR_ACCOUNT_ID` | Yes | — | |
| `NR_LICENSE_KEY` | Yes | — | NR ingest license key |
| `NR_EVENTS_ENDPOINT` | No | EU region | Override for US: `https://insights-collector.newrelic.com/v1/accounts/{account_id}/events` |
| `NR_WEBHOOK_SECRET` | Yes | — | Validates `X-NR-Webhook-Secret` header on incoming webhooks |
| `AGENT_API_KEY` | Yes | — | Required as `X-API-Key` on all operator endpoints |
| `ALLOW_UNAUTHENTICATED_DEV` | No | `false` | Local development only. If `true`, allows missing webhook/operator secrets. Do not use in production. |
| `CONFIRMATION_TTL_MINUTES` | No | `30` | How long a confirmation token stays valid |
| `RESTORE_CONFIDENCE_THRESHOLD` | No | `70` | Minimum confidence score (0–100) to consider a restore point safe. Selection proceeds below threshold but a warning is added to the response. |
| `PREFERRED_REPOSITORIES` | No | `[]` | Repository names that receive a +10 score bonus. Accepts a JSON array or comma-separated string: `repo-primary,offsite-vault` |
| `LOG_LEVEL` | No | `INFO` | |

---

## Restore point selection

The agent does not simply pick the newest clean restore point. Each eligible point
receives a **confidence score (0–100)** based on four components:

### Score components

| Component | Range | Description |
|-----------|-------|-------------|
| **Malware status** | 0–60 | `Clean` → 60 · `Informative` → 30 · unknown → 15 |
| **Safety margin** | 0–25 | Time between the restore point and the alert. ≥24h → 25 · 12–24h → 20 · 4–12h → 12 · 1–4h → 5 · <1h → 0 |
| **Neighbor contamination** | −30–+15 | Examines restore points created *after* the candidate. No infected/suspicious neighbors → +15. Direct neighbor infected → −20. Multiple infected → −30. |
| **Repository bonus** | 0–10 | +10 if `repositoryName` matches any entry in `PREFERRED_REPOSITORIES` |

**Maximum: 110 → clamped to 100. Minimum: clamped to 0.**

The agent always selects the highest-scoring eligible point. If that score is below
`RESTORE_CONFIDENCE_THRESHOLD`, the response includes a `warning` field — the operator
should review carefully before approving.

### Eligible points

A restore point is a candidate if:

- `StartViVMInstantRecovery` is in `allowedOperations`
- `malwareStatus` is **not** `Infected` or `Suspicious`

This includes `Clean`, `Informative`, and restore points with no scan result.

### Score example

```
Scenario: Clean RP created 6 h before alert.
          Direct newer RP is Infected. No preferred repo match.

malwareScore=60 + safetyMarginScore=12 + neighborScore=-20 + repositoryScore=0 = 52
→ below threshold 70
→ warning: "Confidence score 52 is below threshold 70 — review carefully before approving"
```

### Repository enrichment

For each unique `backupId` in the fetched restore points, the agent calls
`GET /api/v1/backups/{id}` to retrieve `repositoryName` and `repositoryId`.
At most 10 additional calls (one per unique backup chain), run concurrently before scoring.

---

## New Relic Workflow setup

### 1. Create a Webhook Destination

**NR One → Alerts → Destinations → Add destination → Webhook**

- URL: `http://<agent-host>:8000/webhook/newrelic`
- Header: `X-NR-Webhook-Secret: <your-secret>` (set `NR_WEBHOOK_SECRET` in `.env`)

### 2. Create a Workflow

**NR One → Alerts → Workflows → Add Workflow**

- Filter: priority `CRITICAL` or `HIGH`, state `ACTIVATED`
- Notification channel: the webhook destination above
- Payload template (copy exactly):

```json
{
  "issueId": {{ json issueId }},
  "title": {{ json annotations.title.[0] }},
  "state": {{ json state }},
  "priority": {{ json priority }},
  "createdAt": {{ createdAt }},
  "vmName": {{ json entitiesData.entities.[0].name }},
  "avScan": false
}
```

> **vmName** is taken from the entity name (`entitiesData.entities.[0].name`).
> The entity name in NR must match the VM hostname as known to Veeam.
>
> **avScan** is hardcoded in the template. Set to `true` to enable AV scan on restore.
> `accumulations.tag.*` variables are not available in notification channel payload templates.

---

## Security

### Webhook (New Relic → Agent)

Set `NR_WEBHOOK_SECRET` in `.env` and add the matching header in the NR Webhook Destination:

```
X-NR-Webhook-Secret: <your-secret>
```

The secret is compared using a timing-safe comparison (`secrets.compare_digest`) to
prevent timing-based secret enumeration.

The webhook endpoint is rate-limited to **10 requests per minute per IP**.

### Operator endpoints

Set `AGENT_API_KEY` in `.env`. All operator endpoints require the header:

```
X-API-Key: <your-key>
```

For local development only, `ALLOW_UNAUTHENTICATED_DEV=true` permits missing secrets. Leave it `false` in production.

### Confirmation tokens

Tokens are single-use UUIDs stored in memory. Duplicate webhooks for the same New Relic `issueId` return the existing pending token instead of creating another one. Only the first 8 characters appear in
logs. Tokens expire after `CONFIRMATION_TTL_MINUTES` (default 30 min) and are purged
every 5 minutes. The in-memory store is capped at 100 pending tokens; requests beyond
that return HTTP 429.

---

## API reference

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| `GET` | `/health` | — | Liveness check, returns pending token count |
| `GET` | `/restore-points/{vm}` | `X-API-Key` | List last 10 RPs before `?failure_time=`, enriched with repository info |
| `POST` | `/webhook/newrelic` | `X-NR-Webhook-Secret` | Receive NR alert, score restore points, return confirmation token |
| `GET` | `/confirm/{token}` | `X-API-Key` | Inspect pending confirmation including full confidence breakdown |
| `POST` | `/confirm/{token}` | `X-API-Key` | Approve or reject recovery |

### Webhook response (POST /webhook/newrelic)

```json
{
  "status": "pending_confirmation",
  "confirmationToken": "uuid",
  "confirmUrl": "/confirm/uuid",
  "vm": "myvm01",
  "expiresIn": "30 minutes",
  "confidence": {
    "malwareScore": 60,
    "safetyMarginScore": 20,
    "neighborScore": 15,
    "repositoryScore": 10,
    "total": 100,
    "threshold": 70,
    "belowThreshold": false,
    "warning": null
  }
}
```

### Confirm body (POST /confirm/{token})

```json
{
  "approved": true,
  "confirmedBy": "ops@corp.com",
  "overrideRestorePointId": "optional-alternative-rp-uuid"
}
```

`overrideRestorePointId` must be one of the eligible restore points from the
pre-validated set (same criteria as the selection: eligible + not Infected/Suspicious).
Any other ID is rejected with HTTP 400.

---

## NR Custom Events

All events use event type `VeeamRecovery` and are queryable in NR One → Query Builder.

### Event overview

| `status` | Trigger | Key fields |
|----------|---------|-----------|
| `NoCleanRestorePoints` | Webhook received, but no clean+eligible restore point exists | `vmName`, `alertId`, `statusesFound` |
| `RecoveryStarted` | Operator approved (`approved: true`) | `vmName`, `restoredVmName`, `restorePointId`, `restorePointTime`, `restoreSessionId`, `confirmedBy`, `alertId`, `avScanEnabled` + all confidence fields |
| `RecoveryRejected` | Operator declined (`approved: false`) | `vmName`, `alertId`, `confirmedBy`, `confidenceTotal`, `confidenceBelowThreshold` |
| `RecoveryReady` | Background poller detects session state `Working` | `vmName`, `restorePointTime`, `restoreSessionId`, `alertId`, `durationSec` |
| `RecoveryExpired` | Confirmation token expired before operator acted | `vmName`, `alertId`, `expiry` |
| `RecoveryFailed` | Session poller timed out after 60 min without reaching `Working` state | `vmName`, `restoreSessionId`, `alertId`, `durationSec` |

All events include `eventType: "VeeamRecovery"`, `status`, and `timestamp`.

### Confidence fields on RecoveryStarted

| Field | Type | Description |
|-------|------|-------------|
| `confidenceTotal` | int (0–100) | Overall score of the selected restore point |
| `confidenceMalwareScore` | int | Contribution from malware status (0 / 30 / 60) |
| `confidenceSafetyMarginScore` | int | Contribution from time distance to failure (0–25) |
| `confidenceNeighborScore` | int | Contamination in newer restore points (−30–+15) |
| `confidenceRepositoryScore` | int | Repository bonus from `PREFERRED_REPOSITORIES` (0 or +10) |
| `confidenceBelowThreshold` | bool | `true` if score was below `RESTORE_CONFIDENCE_THRESHOLD` at time of approval |
| `confidenceWarning` | string | Warning message when `confidenceBelowThreshold` is `true` (omitted otherwise) |

`RecoveryRejected` includes `confidenceTotal` and `confidenceBelowThreshold` so rejections can be correlated with score quality.

### Example queries

```sql
-- All recovery events
SELECT * FROM VeeamRecovery SINCE 7 days ago

-- Recovery count by status
SELECT count(*) FROM VeeamRecovery FACET status SINCE 30 days ago TIMESERIES

-- Average confidence score of approved recoveries
SELECT average(confidenceTotal) FROM VeeamRecovery WHERE status = 'RecoveryStarted' SINCE 30 days ago

-- Recoveries approved despite low confidence
SELECT * FROM VeeamRecovery WHERE status = 'RecoveryStarted' AND confidenceBelowThreshold = true SINCE 30 days ago

-- Rejections correlated with low confidence
SELECT * FROM VeeamRecovery WHERE status = 'RecoveryRejected' AND confidenceBelowThreshold = true SINCE 30 days ago

-- Expired tokens (operators too slow or alert noise)
SELECT count(*) FROM VeeamRecovery WHERE status = 'RecoveryExpired' FACET vmName SINCE 7 days ago

-- Failed recoveries (session never reached Working state)
SELECT * FROM VeeamRecovery WHERE status = 'RecoveryFailed' SINCE 30 days ago

-- VMs with no eligible restore points (needs attention)
SELECT * FROM VeeamRecovery WHERE status = 'NoCleanRestorePoints' SINCE 7 days ago
```

---

## Project structure

```
veeam-recovery-agent/
├── app/
│   ├── main.py          # FastAPI app, routes
│   ├── veeam_client.py  # Veeam B&R REST API client, scoring logic
│   ├── nr_client.py     # New Relic Event API client
│   ├── models.py        # Pydantic models (incl. ConfidenceBreakdown)
│   └── config.py        # Settings (env vars)
├── nr-workflow-template.json
├── Dockerfile
├── docker-compose.yml
├── requirements.txt
└── .env.example
```
