import asyncio
import logging
import secrets
import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

from fastapi import Depends, FastAPI, HTTPException, Header, Query, Request
from fastapi.responses import JSONResponse
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address

from config import settings
from models import (
    ConfirmationRequest,
    ConfirmationResponse,
    NewRelicAlert,
    PendingConfirmation,
    RestorePoint,
    RestorePointsOverview,
    WebhookResponse,
)
from nr_client import NRClient, NRClientError
from veeam_client import VeeamAPIError, VeeamAuthError, VeeamClient

logging.basicConfig(
    level=settings.LOG_LEVEL,
    format="%(asctime)s %(levelname)s %(name)s – %(message)s",
)
logger = logging.getLogger(__name__)

# In-memory confirmation store  {token: PendingConfirmation}
# Cleared on container restart — tokens are short-lived (default 30 min).
_pending: dict[str, PendingConfirmation] = {}
_pending_by_alert: dict[str, str] = {}
_MAX_PENDING = 100  # guard against memory exhaustion
_background_tasks: set[asyncio.Task] = set()

veeam: VeeamClient
nr: NRClient

limiter = Limiter(key_func=get_remote_address)


async def _periodic_purge() -> None:
    """Purge expired tokens every 5 minutes so _pending cannot grow unbounded."""
    while True:
        await asyncio.sleep(300)
        await _purge_expired()


@asynccontextmanager
async def lifespan(app: FastAPI):
    global veeam, nr
    veeam = VeeamClient()
    nr = NRClient()
    purge_task = asyncio.create_task(_periodic_purge())
    logger.info("Veeam Recovery Agent started")
    yield
    purge_task.cancel()
    for task in _background_tasks:
        task.cancel()
    if _background_tasks:
        await asyncio.gather(*_background_tasks, return_exceptions=True)
    await veeam.close()
    await nr.close()
    logger.info("Veeam Recovery Agent stopped")


app = FastAPI(
    title="Veeam Recovery Agent",
    description="New Relic → Veeam Instant VM Recovery bridge",
    version="1.0.0",
    lifespan=lifespan,
)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)


# ── Auth dependency ───────────────────────────────────────────────────────────

def require_api_key(x_api_key: str = Header(default=None)) -> None:
    if settings.ALLOW_UNAUTHENTICATED_DEV and not settings.AGENT_API_KEY:
        return
    if not settings.AGENT_API_KEY or x_api_key != settings.AGENT_API_KEY:
        raise HTTPException(401, "Invalid or missing X-API-Key")


# ── Error handlers ────────────────────────────────────────────────────────────

@app.exception_handler(VeeamAPIError)
async def veeam_api_error_handler(_: Request, exc: VeeamAPIError):
    return JSONResponse(
        status_code=502,
        content={"detail": f"Veeam API error: {exc}"},
    )


@app.exception_handler(VeeamAuthError)
async def veeam_auth_error_handler(_: Request, exc: VeeamAuthError):
    return JSONResponse(
        status_code=503,
        content={"detail": f"Veeam authentication failed: {exc}"},
    )


# ── Helper ────────────────────────────────────────────────────────────────────

_POLL_INTERVAL = 30        # seconds between session status checks
_POLL_TIMEOUT  = 3600      # give up after 60 minutes


async def _poll_session_until_ready(
    session_id: str,
    vm_name: str,
    restore_point_time: str,
    alert_id: str,
    started_at: datetime,
) -> None:
    """
    Background task: poll /api/v1/sessions/{id} every 30 s.
      state == 'Working'           → RecoveryReady, stop polling
      state in ('Stopped','Failed') → RecoveryFailed, stop polling
    Gives up after POLL_TIMEOUT seconds (also sends RecoveryFailed).
    """
    deadline = started_at + timedelta(seconds=_POLL_TIMEOUT)
    logger.info("Session polling started | session=%s | VM=%s", session_id, vm_name)

    while datetime.now(timezone.utc) < deadline:
        await asyncio.sleep(_POLL_INTERVAL)
        try:
            session = await veeam.get_session(session_id)
        except Exception as e:
            logger.warning("Session poll error | session=%s | %s", session_id, e)
            continue

        state = session.get("state")
        logger.debug("Session state | session=%s | state=%s", session_id, state)

        if state not in ("Working", "Stopped", "Failed"):
            continue

        end_time_raw = session.get("endTime") or datetime.now(timezone.utc).isoformat()
        try:
            end_time = datetime.fromisoformat(end_time_raw.replace("Z", "+00:00"))
        except ValueError:
            end_time = datetime.now(timezone.utc)
        duration_sec = int((end_time - started_at).total_seconds())

        logger.info(
            "Session terminal state | session=%s | VM=%s | state=%s | duration=%ds",
            session_id, vm_name, state, duration_sec,
        )

        try:
            if state == "Working":
                await nr.send_recovery_ready(
                    vm_name=vm_name,
                    restore_point_time=restore_point_time,
                    restore_session_id=session_id,
                    alert_id=alert_id,
                    duration_sec=duration_sec,
                )
            else:
                await nr.send_recovery_failed(
                    vm_name=vm_name,
                    restore_session_id=session_id,
                    alert_id=alert_id,
                    duration_sec=duration_sec,
                )
        except NRClientError as e:
            logger.warning("Failed to send NR event for state=%s: %s", state, e)
        return

    duration_sec = int((datetime.now(timezone.utc) - started_at).total_seconds())
    logger.error(
        "Session polling timed out after %ds | session=%s | VM=%s",
        _POLL_TIMEOUT, session_id, vm_name,
    )
    try:
        await nr.send_recovery_failed(
            vm_name=vm_name,
            restore_session_id=session_id,
            alert_id=alert_id,
            duration_sec=duration_sec,
        )
    except NRClientError as e:
        logger.warning("Failed to send NR RecoveryFailed event: %s", e)


async def _purge_expired() -> None:
    now = datetime.now(timezone.utc)
    expired = [
        (t, p) for t, p in _pending.items()
        if datetime.fromisoformat(p.expiry) < now
    ]
    for t, p in expired:
        del _pending[t]
        _pending_by_alert.pop(p.alertId, None)
        try:
            await nr.send_recovery_expired(
                vm_name=p.vmName,
                alert_id=p.alertId,
                expiry=p.expiry,
            )
        except NRClientError as e:
            logger.warning("Failed to send NR RecoveryExpired event: %s", e)
    if expired:
        logger.debug("Purged %d expired confirmation token(s)", len(expired))


# ── Routes ────────────────────────────────────────────────────────────────────

@app.get("/health")
async def health() -> dict[str, Any]:
    return {"status": "ok", "pendingConfirmations": len(_pending)}


@app.get("/restore-points/{vm_name}", response_model=RestorePointsOverview, dependencies=[Depends(require_api_key)])
async def get_restore_points(
    vm_name: str,
    failure_time: Optional[str] = Query(
        default=None,
        description="ISO 8601 UTC timestamp of the failure. Defaults to now.",
    ),
) -> RestorePointsOverview:
    """
    Returns the last 10 restore points for a VMware VM before the given
    failure_time (default: now). All malware statuses are included so the
    operator has full visibility before making a recovery decision.

    Also indicates how many are clean and eligible for Instant VM Recovery.
    """
    if failure_time:
        before = datetime.fromisoformat(failure_time.replace("Z", "+00:00"))
    else:
        before = datetime.now(timezone.utc)

    points = await veeam.get_restore_points(vm_name, before_time=before, limit=10)
    await veeam.enrich_with_repository(points)
    clean_eligible = veeam.filter_clean_eligible(points)

    return RestorePointsOverview(
        vm=vm_name,
        failureTime=before.strftime("%Y-%m-%dT%H:%M:%S.000Z"),
        totalFound=len(points),
        cleanAndEligible=len(clean_eligible),
        restorePoints=points,
    )


@app.post("/webhook/newrelic", response_model=WebhookResponse)
@limiter.limit("10/minute")
async def newrelic_webhook(
    request: Request,
    alert: NewRelicAlert,
    x_nr_webhook_secret: str = Header(default=None),
) -> WebhookResponse:
    """
    Receive a New Relic alert webhook.

    Required NR workflow template custom fields:
      vmName  → affected VM name
      avScan  → optional, default true
    """
    if not settings.NR_WEBHOOK_SECRET and settings.ALLOW_UNAUTHENTICATED_DEV:
        pass
    elif not secrets.compare_digest(
        (x_nr_webhook_secret or "").encode(),
        settings.NR_WEBHOOK_SECRET.encode(),
    ):
        raise HTTPException(401, "Invalid webhook secret")

    if alert.state not in ("CREATED", "ACTIVATED"):
        logger.info("Alert %s ignored (state=%s)", alert.issueId, alert.state)
        return WebhookResponse(
            status="ignored",
            reason=f"Alert state '{alert.state}' requires no action",
        )

    await _purge_expired()

    existing_token = _pending_by_alert.get(alert.issueId)
    existing = _pending.get(existing_token or "")
    if existing:
        logger.info(
            "Duplicate alert received; returning existing confirmation | alert=%s | token=%s...",
            alert.issueId, existing_token[:8],
        )
        return WebhookResponse(
            status="pending_confirmation",
            confirmationToken=existing_token,
            confirmUrl=f"/confirm/{existing_token}",
            vm=existing.vmName,
            confidence=existing.confidence,
            expiresIn=f"{settings.CONFIRMATION_TTL_MINUTES} minutes",
        )

    if len(_pending) >= _MAX_PENDING:
        raise HTTPException(429, "Too many pending confirmations — try again later")

    failure_time = datetime.fromtimestamp(alert.createdAt / 1000, tz=timezone.utc)
    logger.info(
        "Processing alert | id=%s | VM=%s | failure_time=%s",
        alert.issueId, alert.vmName, failure_time,
    )

    # Fetch last 10 restore points (all statuses) for the affected VM
    all_points = await veeam.get_restore_points(
        vm_name=alert.vmName,
        before_time=failure_time,
        limit=10,
    )
    if not all_points:
        raise HTTPException(
            404,
            f"No restore points found before {failure_time.isoformat()} "
            f"for VM '{alert.vmName}'",
        )

    # Enrich with repository info (adds repositoryId / repositoryName to each point)
    await veeam.enrich_with_repository(all_points)

    # Score and select best eligible restore point
    selection = veeam.select_best_restore_point(all_points, failure_time)
    if selection is None:
        statuses = [p.malwareStatus for p in all_points]
        try:
            await nr.send_no_clean_restore_points(
                vm_name=alert.vmName,
                alert_id=alert.issueId,
                statuses_found=statuses,
            )
        except NRClientError as e:
            logger.warning("Failed to send NR event: %s", e)
        raise HTTPException(
            409,
            f"Found {len(all_points)} restore point(s) for VM '{alert.vmName}' "
            f"but none are eligible for Instant VM Recovery. "
            f"Statuses: {statuses}",
        )

    best, confidence = selection
    alternatives = [p for p in veeam.filter_selectable(all_points) if p.id != best.id]

    if confidence.belowThreshold:
        logger.warning(
            "Low-confidence restore point selected | VM=%s | score=%d | threshold=%d | RP=%s",
            alert.vmName, confidence.total, confidence.threshold, best.id,
        )

    token = str(uuid.uuid4())
    expiry = datetime.now(timezone.utc) + timedelta(minutes=settings.CONFIRMATION_TTL_MINUTES)
    _pending[token] = PendingConfirmation(
        vmName=alert.vmName,
        restorePointId=best.id,
        restorePointTime=best.creationTime,
        malwareStatus=best.malwareStatus,
        alertId=alert.issueId,
        avScan=alert.avScan,
        alternativePoints=alternatives,
        expiry=expiry.isoformat(),
        confidence=confidence,
    )
    _pending_by_alert[alert.issueId] = token

    logger.info(
        "Confirmation token created | token=%s... | VM=%s | RP=%s | expires=%s",
        token[:8], alert.vmName, best.id, expiry,
    )

    return WebhookResponse(
        status="pending_confirmation",
        confirmationToken=token,
        confirmUrl=f"/confirm/{token}",
        vm=alert.vmName,
        confidence=confidence,
        expiresIn=f"{settings.CONFIRMATION_TTL_MINUTES} minutes",
    )


@app.get("/confirm/{token}", response_model=PendingConfirmation, dependencies=[Depends(require_api_key)])
async def get_confirmation(token: str) -> PendingConfirmation:
    """Inspect a pending confirmation before approving."""
    pending = _pending.get(token)
    if not pending:
        raise HTTPException(404, "Token not found or already used")
    if datetime.now(timezone.utc) > datetime.fromisoformat(pending.expiry):
        del _pending[token]
        _pending_by_alert.pop(pending.alertId, None)
        try:
            await nr.send_recovery_expired(
                vm_name=pending.vmName,
                alert_id=pending.alertId,
                expiry=pending.expiry,
            )
        except NRClientError as e:
            logger.warning("Failed to send NR RecoveryExpired event: %s", e)
        raise HTTPException(410, "Confirmation token expired")
    return pending


@app.post("/confirm/{token}", response_model=ConfirmationResponse, dependencies=[Depends(require_api_key)])
async def confirm_recovery(
    token: str,
    req: ConfirmationRequest,
) -> ConfirmationResponse:
    """
    Approve or reject a pending recovery.
    Set `overrideRestorePointId` to pick an alternative from the pre-validated
    clean+eligible set. Any ID outside that set is rejected.
    """
    pending = _pending.get(token)
    if not pending:
        raise HTTPException(404, "Token not found or already used")

    if datetime.now(timezone.utc) > datetime.fromisoformat(pending.expiry):
        del _pending[token]
        _pending_by_alert.pop(pending.alertId, None)
        try:
            await nr.send_recovery_expired(
                vm_name=pending.vmName,
                alert_id=pending.alertId,
                expiry=pending.expiry,
            )
        except NRClientError as e:
            logger.warning("Failed to send NR RecoveryExpired event: %s", e)
        raise HTTPException(410, "Confirmation token expired")

    if not req.approved:
        del _pending[token]  # consume — single use
        _pending_by_alert.pop(pending.alertId, None)
        logger.info(
            "Recovery rejected | VM=%s | by=%s | alert=%s",
            pending.vmName, req.confirmedBy, pending.alertId,
        )
        try:
            await nr.send_recovery_rejected(
                vm_name=pending.vmName,
                alert_id=pending.alertId,
                confirmed_by=req.confirmedBy,
                confidence_total=pending.confidence.total,
                confidence_below_threshold=pending.confidence.belowThreshold,
            )
        except NRClientError as e:
            logger.warning("Failed to send NR event: %s", e)
        return ConfirmationResponse(status="rejected", confirmedBy=req.confirmedBy)

    # Validate override against the pre-vetted selectable restore points
    restore_point_id = pending.restorePointId
    if req.overrideRestorePointId:
        valid_ids = {p.id for p in pending.alternativePoints} | {pending.restorePointId}
        if req.overrideRestorePointId not in valid_ids:
            raise HTTPException(
                400,
                "overrideRestorePointId is not in the pre-validated selectable restore points. "
                "Re-trigger via webhook to get a fresh set.",
            )
        restore_point_id = req.overrideRestorePointId
        logger.info("Operator selected alternative RP: %s", restore_point_id)

    result = await veeam.instant_vm_recovery(
        restore_point_id=restore_point_id,
        vm_name=pending.vmName,
        av_scan=pending.avScan,
    )

    del _pending[token]  # consume only after validation and successful Veeam start
    _pending_by_alert.pop(pending.alertId, None)

    restored_name = f"{pending.vmName}-NewRelic"
    session_id = result.get("id", "")
    started_at = datetime.now(timezone.utc)
    logger.info(
        "Instant VM Recovery started | VM=%s → %s | session=%s | by=%s",
        pending.vmName, restored_name, session_id, req.confirmedBy,
    )

    if session_id:
        task = asyncio.create_task(_poll_session_until_ready(
            session_id=session_id,
            vm_name=pending.vmName,
            restore_point_time=pending.restorePointTime,
            alert_id=pending.alertId,
            started_at=started_at,
        ))
        _background_tasks.add(task)
        task.add_done_callback(_background_tasks.discard)

    try:
        await nr.send_recovery_started(
            vm_name=pending.vmName,
            restored_vm_name=restored_name,
            restore_point_id=restore_point_id,
            restore_point_time=pending.restorePointTime,
            restore_session_id=session_id,
            confirmed_by=req.confirmedBy,
            alert_id=pending.alertId,
            av_scan=pending.avScan,
            confidence_total=pending.confidence.total,
            confidence_malware_score=pending.confidence.malwareScore,
            confidence_safety_margin_score=pending.confidence.safetyMarginScore,
            confidence_neighbor_score=pending.confidence.neighborScore,
            confidence_repository_score=pending.confidence.repositoryScore,
            confidence_below_threshold=pending.confidence.belowThreshold,
            confidence_warning=pending.confidence.warning,
        )
    except NRClientError as e:
        logger.warning("Failed to send NR event: %s", e)

    return ConfirmationResponse(
        status="recovery_started",
        confirmedBy=req.confirmedBy,
        restoredVmName=restored_name,
        restoreSessionId=session_id,
        restoreSession=result,
    )
