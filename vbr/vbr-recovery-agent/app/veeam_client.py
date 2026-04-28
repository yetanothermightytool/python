import asyncio
import httpx
import logging
from datetime import datetime, timedelta, timezone
from typing import Optional

from config import settings
from models import ConfidenceBreakdown, RestorePoint

logger = logging.getLogger(__name__)


class VeeamAuthError(Exception):
    pass


class VeeamAPIError(Exception):
    def __init__(self, status_code: int, detail: str):
        self.status_code = status_code
        super().__init__(f"Veeam API {status_code}: {detail}")


class VeeamClient:
    """Async Veeam B&R REST API client (API version 1.3-rev1)."""

    def __init__(self):
        self._base = settings.VEEAM_URL.rstrip("/")
        self._api_version = settings.VEEAM_API_VERSION
        self._token: Optional[str] = None
        self._token_expiry: Optional[datetime] = None
        self._http = httpx.AsyncClient(
            verify=settings.VEEAM_VERIFY_SSL,
            timeout=30.0,
        )

    # ── Auth ──────────────────────────────────────────────────────────────────

    async def _authenticate(self) -> None:
        logger.info("Authenticating against Veeam API")
        try:
            r = await self._http.post(
                f"{self._base}/api/oauth2/token",
                data={
                    "grant_type": "password",
                    "username": settings.VEEAM_USERNAME,
                    "password": settings.VEEAM_PASSWORD,
                    "use_short_term_refresh": "false",
                },
                headers={
                    "Content-Type": "application/x-www-form-urlencoded",
                    "x-api-version": self._api_version,
                },
            )
        except httpx.RequestError as e:
            raise VeeamAuthError(f"Connection failed: {e}") from e

        if r.status_code != 200:
            raise VeeamAuthError(f"Auth failed ({r.status_code}): {r.text}")

        data = r.json()
        self._token = data["access_token"]
        # Refresh 60 s before actual expiry to avoid races
        self._token_expiry = datetime.now(timezone.utc) + timedelta(
            seconds=data.get("expires_in", 3600) - 60
        )
        logger.debug("Veeam token acquired, expires %s", self._token_expiry)

    async def _headers(self) -> dict:
        if not self._token or datetime.now(timezone.utc) >= self._token_expiry:
            await self._authenticate()
        return {
            "Authorization": f"Bearer {self._token}",
            "x-api-version": self._api_version,
            "Content-Type": "application/json",
        }

    # ── Generic request helpers ───────────────────────────────────────────────

    async def _get(self, path: str, params: dict = None) -> dict:
        headers = await self._headers()
        try:
            r = await self._http.get(
                f"{self._base}{path}", headers=headers, params=params
            )
        except httpx.RequestError as e:
            raise VeeamAPIError(503, f"Request failed: {e}") from e
        if not r.is_success:
            raise VeeamAPIError(r.status_code, r.text)
        return r.json()

    async def _post(self, path: str, body: dict) -> dict:
        headers = await self._headers()
        try:
            r = await self._http.post(
                f"{self._base}{path}", headers=headers, json=body
            )
        except httpx.RequestError as e:
            raise VeeamAPIError(503, f"Request failed: {e}") from e
        if not r.is_success:
            raise VeeamAPIError(r.status_code, r.text)
        return r.json()

    # ── Restore points ────────────────────────────────────────────────────────

    async def get_restore_points(
        self,
        vm_name: str,
        before_time: datetime,
        limit: int = 10,
    ) -> list[RestorePoint]:
        """
        Fetch the last `limit` restore points for a VMware VM before `before_time`.
        Returns all malware statuses — caller decides what to do with them.

        Uses GET /api/v1/restorePoints with:
          nameFilter        = vm_name   (matches restore point name field = VM name)
          platformNameFilter = VMware
          createdBeforeFilter = before_time (ISO 8601)
          orderColumn       = CreationTime
          orderAsc          = false     (newest first)
          limit             = 10
        """
        data = await self._get(
            "/api/v1/restorePoints",
            params={
                "nameFilter": vm_name,
                "platformNameFilter": "VMware",
                "createdBeforeFilter": before_time.strftime("%Y-%m-%dT%H:%M:%S.000Z"),
                "orderColumn": "CreationTime",
                "orderAsc": False,
                "skip": 0,
                "limit": limit,
            },
        )

        points = [RestorePoint(**p) for p in data.get("data", [])]

        logger.info(
            "Restore points for VM '%s' before %s: found=%d",
            vm_name,
            before_time.isoformat(),
            len(points),
        )
        for p in points:
            logger.debug(
                "  RP %s | %s | type=%-10s | malware=%-12s | eligible=%s",
                p.id,
                p.creationTime,
                p.type,
                p.malwareStatus,
                p.is_instant_recovery_eligible,
            )

        return points

    def filter_clean_eligible(self, points: list[RestorePoint]) -> list[RestorePoint]:
        """Clean + eligible — used for the operator overview count."""
        return [p for p in points if p.is_clean and p.is_instant_recovery_eligible]

    def filter_selectable(self, points: list[RestorePoint]) -> list[RestorePoint]:
        """
        Eligible for recovery selection: must have StartViVMInstantRecovery AND
        malware status is not Infected or Suspicious.
        Includes Clean, Informative, and unknown (None) statuses.
        """
        return [
            p for p in points
            if p.is_instant_recovery_eligible
            and p.malwareStatus not in ("Infected", "Suspicious")
        ]

    # ── Repository enrichment ─────────────────────────────────────────────────

    async def get_backup(self, backup_id: str) -> dict:
        """GET /api/v1/backups/{id} — returns backup details including repository info."""
        return await self._get(f"/api/v1/backups/{backup_id}")

    async def enrich_with_repository(self, points: list[RestorePoint]) -> None:
        """
        Enrich RestorePoints in-place with repositoryId / repositoryName.
        Fetches unique backupIds concurrently.
        """
        unique_ids = list({p.backupId for p in points if p.backupId})

        async def _fetch(bid: str) -> tuple[str, dict]:
            try:
                return bid, await self.get_backup(bid)
            except VeeamAPIError as e:
                logger.warning("Could not fetch backup info for %s: %s", bid, e)
                return bid, {}

        results = await asyncio.gather(*[_fetch(bid) for bid in unique_ids])
        cache = dict(results)

        for point in points:
            info = cache.get(point.backupId or "", {})
            point.repositoryId = info.get("repositoryId")
            point.repositoryName = info.get("repositoryName")

    # ── Confidence scoring ────────────────────────────────────────────────────

    _MALWARE_SCORES: dict = {
        "Clean": 60,
        "Informative": 30,
        "Suspicious": 0,
        "Infected": 0,
    }

    def score_restore_point(
        self,
        point: RestorePoint,
        all_points: list[RestorePoint],
        failure_time: datetime,
    ) -> ConfidenceBreakdown:
        """
        Score a restore point 0–100 based on:
          - Malware status          (0–60)
          - Safety margin           (0–25)  time distance to failure_time
          - Neighbor contamination  (-30–+15)  infection state of newer RPs
          - Repository bonus        (0–10)   PREFERRED_REPOSITORIES match
        """
        threshold = settings.RESTORE_CONFIDENCE_THRESHOLD

        # 1. Malware status score
        malware_score = self._MALWARE_SCORES.get(point.malwareStatus or "", 15)

        # 2. Safety margin — how far before failure_time was this RP created?
        rp_time = datetime.fromisoformat(
            point.creationTime.replace("Z", "+00:00")
        )
        age_hours = (failure_time - rp_time).total_seconds() / 3600

        if age_hours >= 24:
            margin_score = 25
        elif age_hours >= 12:
            margin_score = 20
        elif age_hours >= 4:
            margin_score = 12
        elif age_hours >= 1:
            margin_score = 5
        else:
            margin_score = 0

        # 3. Neighbor contamination — inspect restore points newer than this one
        newer = [
            p for p in all_points
            if datetime.fromisoformat(
                p.creationTime.replace("Z", "+00:00")
            ) > rp_time
        ]
        infected = [p for p in newer if p.malwareStatus == "Infected"]
        suspicious = [p for p in newer if p.malwareStatus == "Suspicious"]

        if not infected and not suspicious:
            neighbor_score = 15
        else:
            # Direct neighbor = chronologically closest newer RP (oldest among newer)
            direct = min(newer, key=lambda p: datetime.fromisoformat(p.creationTime.replace("Z", "+00:00"))) if newer else None
            if len(infected) >= 2 or (infected and suspicious):
                neighbor_score = -30
            elif direct and direct.malwareStatus == "Infected":
                neighbor_score = -20
            elif infected:
                neighbor_score = -10
            elif direct and direct.malwareStatus == "Suspicious":
                neighbor_score = -10
            else:
                neighbor_score = -5

        # 4. Repository bonus
        repo_score = 0
        preferred = settings.preferred_repositories_list
        if preferred and point.repositoryName:
            if any(r.lower() in point.repositoryName.lower() for r in preferred):
                repo_score = 10

        total = max(0, min(100, malware_score + margin_score + neighbor_score + repo_score))
        below = total < threshold

        return ConfidenceBreakdown(
            malwareScore=malware_score,
            safetyMarginScore=margin_score,
            neighborScore=neighbor_score,
            repositoryScore=repo_score,
            total=total,
            threshold=threshold,
            belowThreshold=below,
            warning=(
                f"Confidence score {total} is below threshold {threshold} — "
                "review carefully before approving"
            ) if below else None,
        )

    def select_best_restore_point(
        self,
        all_points: list[RestorePoint],
        failure_time: datetime,
    ) -> tuple[RestorePoint, ConfidenceBreakdown] | None:
        """
        Score all selectable restore points and return the highest-scoring one.
        Returns None if no eligible points exist at all.
        """
        candidates = self.filter_selectable(all_points)
        if not candidates:
            return None

        scored = [
            (p, self.score_restore_point(p, all_points, failure_time))
            for p in candidates
        ]
        scored.sort(key=lambda x: x[1].total, reverse=True)

        best, score = scored[0]
        logger.info(
            "Restore point selected | RP=%s | score=%d | threshold=%d | "
            "malware=%s | margin=%d | neighbor=%d | repo=%d",
            best.id, score.total, score.threshold,
            score.malwareScore, score.safetyMarginScore,
            score.neighborScore, score.repositoryScore,
        )
        return best, score

    # ── Instant VM Recovery ───────────────────────────────────────────────────

    async def instant_vm_recovery(
        self,
        restore_point_id: str,
        vm_name: str,
        av_scan: bool,
    ) -> dict:
        """
        Trigger Instant VM Recovery to vSphere.
        Restored VM is named `{vm_name}-NewRelic`.

        POST /api/v1/restore/instantRecovery/vSphere/vm
        """
        body = {
            "nicsEnabled": False,
            "powerUp": True,
            "reason": "Instant Recovery triggered by New Relic APM alert",
            "restorePointId": restore_point_id,
            "secureRestore": {
                "antivirusScanEnabled": av_scan,
                "entireVolumeScanEnabled": False,
                "virusDetectionAction": "DisableNetwork",
            },
            "type": "Customized",
            "vmTagsRestoreEnabled": True,
            "destination": {
                "restoredVmName": f"{vm_name}-NewRelic",
            },
            "datastore": {
                "redirectEnabled": False,
            },
        }
        logger.info(
            "Triggering Instant VM Recovery | VM=%s → %s-NewRelic | RP=%s | AV=%s",
            vm_name, vm_name, restore_point_id, av_scan,
        )
        return await self._post(
            "/api/v1/restore/instantRecovery/vSphere/vm", body
        )

    async def get_session(self, session_id: str) -> dict:
        """GET /api/v1/sessions/{id} — returns session state and result."""
        return await self._get(f"/api/v1/sessions/{session_id}")

    async def close(self) -> None:
        await self._http.aclose()
