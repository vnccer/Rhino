from __future__ import annotations

import json
import ssl
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable


@dataclass(frozen=True)
class UploadResult:
    success: bool
    retryable: bool
    status: int | None
    error: str | None = None
    retry_after: float | None = None


class ApiClient:
    def __init__(
        self,
        api_url: str,
        api_key: str,
        timeout: float,
        ca_cert: Path | None = None,
        opener: Callable[..., Any] | None = None,
    ) -> None:
        self.api_url = api_url.rstrip("/")
        self.api_key = api_key
        self.timeout = timeout
        self.context = ssl.create_default_context(cafile=str(ca_cert) if ca_cert else None)
        self._opener = opener or urllib.request.urlopen

    def _post(self, path: str, payload: Any) -> UploadResult:
        body = json.dumps(payload, ensure_ascii=True, separators=(",", ":")).encode("utf-8")
        request = urllib.request.Request(
            f"{self.api_url}{path}",
            data=body,
            method="POST",
            headers={
                "Content-Type": "application/json",
                "User-Agent": "aasm-linux-collector/0.1.1",
                "X-Collector-API-Key": self.api_key,
            },
        )
        try:
            with self._opener(request, timeout=self.timeout, context=self.context) as response:
                response.read()
                status = int(response.status)
                return UploadResult(status in {200, 201}, False, status)
        except urllib.error.HTTPError as error:
            retryable = error.code == 429 or error.code >= 500
            retry_after: float | None = None
            if error.code == 429:
                try:
                    retry_after = float(error.headers.get("Retry-After", ""))
                except (TypeError, ValueError):
                    pass
            try:
                detail = error.read(500).decode("utf-8", "replace")
            except OSError:
                detail = str(error.reason)
            return UploadResult(False, retryable, error.code, detail, retry_after)
        except (urllib.error.URLError, TimeoutError, OSError) as error:
            return UploadResult(False, True, None, str(error))

    def send_events(self, events: list[dict[str, Any]]) -> UploadResult:
        return self._post("/api/collector/events", events)

    def send_heartbeat(self, payload: dict[str, Any]) -> UploadResult:
        return self._post("/api/collector/heartbeat", payload)


def enroll(
    api_url: str,
    token: str,
    host: dict[str, str],
    timeout: float,
    ca_cert: Path | None = None,
) -> dict[str, Any]:
    context = ssl.create_default_context(cafile=str(ca_cert) if ca_cert else None)
    body = json.dumps(
        {
            "enrollment_token": token,
            "host_id": host["host_id"],
            "hostname": host["hostname"],
            "os": host["os"],
            "os_version": host["os_version"],
            "collector_version": host["collector_version"],
        },
        separators=(",", ":"),
    ).encode("utf-8")
    request = urllib.request.Request(
        f"{api_url.rstrip('/')}/api/collectors/enroll",
        data=body,
        method="POST",
        headers={"Content-Type": "application/json", "User-Agent": "aasm-linux-collector/0.1.1"},
    )
    with urllib.request.urlopen(request, timeout=timeout, context=context) as response:
        return json.loads(response.read().decode("utf-8"))

