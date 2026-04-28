import httpx
import logging
from datetime import datetime, timezone
from typing import Any, Optional

from config import settings

logger = logging.getLogger(__name__)

# Custom event type name visible in NR query builder / dashboards
NR_EVENT_TYPE = "VeeamRecovery"


class NRClientError(Exception):
    pass


class NRClient:
    """
    New Relic Event API client (EU region).
    Sends custom VeeamRecovery events to NRDB so recovery actions
    are queryable in dashboards and alerts.

    Events endpoint (EU):
      POST https://insights-collector.eu01.nr-data.net/v1/accounts/{accountId}/events
    """

    def __init__(self):
        self._endpoint = settings.NR_EVENTS_ENDPOINT.format(
            account_id=settings.NR_ACCOUNT_ID
        )
        self._http = httpx.AsyncClient(timeout=15.0)

    async def _send(self, events: list[dict[str, Any]]) -> None:
        """POST one or more events to the NR Event API."""
        try:
            r = await self._http.post(
                self._endpoint,
                json=events,
                headers={
                    "Api-Key": settings.NR_LICENSE_KEY,
                    "Content-Type": "application/json",
                },
            )
        except httpx.RequestError as e:
            raise NRClientError(f"NR Event API request failed: {e}") from e
        if not r.is_success:
            raise NRClientError(
                f"NR Event API returned {r.status_code}: {r.text}"
            )
        logger.debug("NR event sent: %s", events)

    # ── Public helpers ────────────────────────────────────────────────────────

    async def send_recovery_started(
        self,
        *,
        vm_name: str,
        restored_vm_name: str,
        restore_point_id: str,
        restore_point_time: str,
        restore_session_id: str,
        confirmed_by: str,
        alert_id: str,
        av_scan: bool,
        confidence_total: int,
        confidence_malware_score: int,
        confidence_safety_margin_score: int,
        confidence_neighbor_score: int,
        confidence_repository_score: int,
        confidence_below_threshold: bool,
        confidence_warning: Optional[str] = None,
    ) -> None:
        event: dict[str, Any] = {
            "eventType": NR_EVENT_TYPE,
            "status": "RecoveryStarted",
            "vmName": vm_name,
            "restoredVmName": restored_vm_name,
            "restorePointId": restore_point_id,
            "restorePointTime": restore_point_time,
            "restoreSessionId": restore_session_id,
            "confirmedBy": confirmed_by,
            "alertId": alert_id,
            "avScanEnabled": av_scan,
            "confidenceTotal": confidence_total,
            "confidenceMalwareScore": confidence_malware_score,
            "confidenceSafetyMarginScore": confidence_safety_margin_score,
            "confidenceNeighborScore": confidence_neighbor_score,
            "confidenceRepositoryScore": confidence_repository_score,
            "confidenceBelowThreshold": confidence_below_threshold,
            "timestamp": int(datetime.now(timezone.utc).timestamp()),
        }
        if confidence_warning:
            event["confidenceWarning"] = confidence_warning
        await self._send([event])
        logger.info(
            "NR event sent: RecoveryStarted | VM=%s → %s | session=%s",
            vm_name, restored_vm_name, restore_session_id,
        )

    async def send_recovery_rejected(
        self,
        *,
        vm_name: str,
        alert_id: str,
        confirmed_by: str,
        confidence_total: int,
        confidence_below_threshold: bool,
    ) -> None:
        await self._send([{
            "eventType": NR_EVENT_TYPE,
            "status": "RecoveryRejected",
            "vmName": vm_name,
            "alertId": alert_id,
            "confirmedBy": confirmed_by,
            "confidenceTotal": confidence_total,
            "confidenceBelowThreshold": confidence_below_threshold,
            "timestamp": int(datetime.now(timezone.utc).timestamp()),
        }])
        logger.info(
            "NR event sent: RecoveryRejected | VM=%s | by=%s", vm_name, confirmed_by
        )

    async def send_recovery_ready(
        self,
        *,
        vm_name: str,
        restore_point_time: str,
        restore_session_id: str,
        alert_id: str,
        duration_sec: int,
    ) -> None:
        await self._send([{
            "eventType": NR_EVENT_TYPE,
            "status": "RecoveryReady",
            "vmName": vm_name,
            "restorePointTime": restore_point_time,
            "restoreSessionId": restore_session_id,
            "alertId": alert_id,
            "durationSec": duration_sec,
            "timestamp": int(datetime.now(timezone.utc).timestamp()),
        }])
        logger.info(
            "NR event sent: RecoveryReady | VM=%s | session=%s | duration=%ds",
            vm_name, restore_session_id, duration_sec,
        )

    async def send_no_clean_restore_points(
        self,
        *,
        vm_name: str,
        alert_id: str,
        statuses_found: list[str],
    ) -> None:
        await self._send([{
            "eventType": NR_EVENT_TYPE,
            "status": "NoCleanRestorePoints",
            "vmName": vm_name,
            "alertId": alert_id,
            "statusesFound": ", ".join(statuses_found),
            "timestamp": int(datetime.now(timezone.utc).timestamp()),
        }])
        logger.warning(
            "NR event sent: NoCleanRestorePoints | VM=%s | statuses=%s",
            vm_name, statuses_found,
        )

    async def send_recovery_expired(
        self,
        *,
        vm_name: str,
        alert_id: str,
        expiry: str,
    ) -> None:
        await self._send([{
            "eventType": NR_EVENT_TYPE,
            "status": "RecoveryExpired",
            "vmName": vm_name,
            "alertId": alert_id,
            "expiry": expiry,
            "timestamp": int(datetime.now(timezone.utc).timestamp()),
        }])
        logger.info(
            "NR event sent: RecoveryExpired | VM=%s | alert=%s", vm_name, alert_id
        )

    async def send_recovery_failed(
        self,
        *,
        vm_name: str,
        restore_session_id: str,
        alert_id: str,
        duration_sec: int,
    ) -> None:
        await self._send([{
            "eventType": NR_EVENT_TYPE,
            "status": "RecoveryFailed",
            "vmName": vm_name,
            "restoreSessionId": restore_session_id,
            "alertId": alert_id,
            "durationSec": duration_sec,
            "timestamp": int(datetime.now(timezone.utc).timestamp()),
        }])
        logger.error(
            "NR event sent: RecoveryFailed | VM=%s | session=%s | duration=%ds",
            vm_name, restore_session_id, duration_sec,
        )

    async def close(self) -> None:
        await self._http.aclose()
