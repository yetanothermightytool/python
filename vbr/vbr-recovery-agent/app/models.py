from pydantic import BaseModel, Field
from typing import Optional, Any
from datetime import datetime, timezone


# ── Inbound: New Relic alert webhook ─────────────────────────────────────────
# NR sends a configurable JSON payload via Notification Channel / Workflow.
# vmName must be mapped in the NR workflow template as a custom tag.

class NewRelicAlert(BaseModel):
    issueId: str
    title: str
    # CREATED | ACTIVATED | ACKNOWLEDGED | RESOLVED | CLOSED
    state: str
    priority: str                           # CRITICAL | HIGH | MEDIUM | LOW
    # Epoch milliseconds — when the issue was first opened
    createdAt: int
    # Custom fields injected via NR workflow template:
    vmName: str                             # {{ accumulations.tag.vmName }}
    avScan: bool = True                     # {{ accumulations.tag.avScan }}


# ── Veeam restore point (ObjectRestorePointModel) ────────────────────────────

class RestorePoint(BaseModel):
    id: str
    name: str
    platformName: str
    creationTime: str
    backupId: str
    type: Optional[str] = None             # Full | Increment | Rollback | Snapshot | Cdp
    malwareStatus: Optional[str] = None    # Clean | Suspicious | Infected | Informative
    allowedOperations: list[str] = []
    guestOsFamily: Optional[str] = None    # Windows | Linux | Unknown | Other
    backupFileId: Optional[str] = None
    # Enriched via /api/v1/backups/{backupId}
    repositoryId: Optional[str] = None
    repositoryName: Optional[str] = None

    @property
    def is_instant_recovery_eligible(self) -> bool:
        return "StartViVMInstantRecovery" in self.allowedOperations

    @property
    def is_clean(self) -> bool:
        return self.malwareStatus == "Clean"


# ── Confidence score breakdown ────────────────────────────────────────────────

class ConfidenceBreakdown(BaseModel):
    malwareScore: int           # 0 / 30 / 60 based on malware status
    safetyMarginScore: int      # 0–25 based on time distance to failure
    neighborScore: int          # -30–+15 based on contamination in newer RPs
    repositoryScore: int        # 0 or +10 if repo matches PREFERRED_REPOSITORIES
    total: int                  # clamped 0–100
    threshold: int
    belowThreshold: bool
    warning: Optional[str] = None


# ── Internal: pending restore confirmation ───────────────────────────────────

class PendingConfirmation(BaseModel):
    vmName: str
    restorePointId: str
    restorePointTime: str
    malwareStatus: Optional[str]
    alertId: str
    avScan: bool
    alternativePoints: list[RestorePoint]
    expiry: str
    confidence: ConfidenceBreakdown
    createdAt: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


# ── Inbound: operator confirmation ───────────────────────────────────────────

class ConfirmationRequest(BaseModel):
    approved: bool
    confirmedBy: str
    # Optionally pick an alternative restore point from the pre-validated set
    overrideRestorePointId: Optional[str] = None


# ── Outbound responses ───────────────────────────────────────────────────────

class WebhookResponse(BaseModel):
    status: str
    confirmationToken: Optional[str] = None
    confirmUrl: Optional[str] = None
    vm: Optional[str] = None
    confidence: Optional[ConfidenceBreakdown] = None
    expiresIn: Optional[str] = None
    reason: Optional[str] = None


class ConfirmationResponse(BaseModel):
    status: str
    confirmedBy: Optional[str] = None
    restoredVmName: Optional[str] = None
    restoreSessionId: Optional[str] = None
    restoreSession: Optional[dict[str, Any]] = None


class RestorePointsOverview(BaseModel):
    vm: str
    failureTime: str
    totalFound: int
    cleanAndEligible: int
    restorePoints: list[RestorePoint]
