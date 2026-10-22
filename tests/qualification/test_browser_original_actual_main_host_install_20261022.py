"""Host-only immutable four-original Browser service in actual mounted main.

The positive witness is **synthetic independently signed test material**,
never live host enrollment, browser target-effects or production certification.
No application lifespan/database/network/browser/third-party target is started.
"""

from __future__ import annotations

from typing import Any

import httpx
import pytest

from ai_osop.api import main
from ai_osop.api.browser_current_custody_readback import (
    BrowserCurrentCustodyReadback,
    install_host_browser_original_enrollment,
)
from ai_osop.api.browser_host_original_enrollment_20261022 import (
    BrowserHostOriginalEnrollment,
)
from tests.qualification.test_browser_custody_readback_join_20261021 import _token
from tests.qualification.test_browser_host_original_enrollment_20261022 import (
    api_case,
    bridge_case,
    custody_case,
    enrolled,
    operator_case,
    signed_current_case,
)

_SLOT = "_independently_host_enrolled_browser_original_20261022"


@pytest.mark.asyncio
async def test_mounted_main_uses_host_enrolled_signed_four_originals_readonly(
    enrolled: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    case = enrolled
    host = BrowserHostOriginalEnrollment(**case["host_opts"])
    assert not hasattr(main.app.state, _SLOT)
    install_host_browser_original_enrollment(main.app, host)
    assert type(getattr(main.app.state, _SLOT)) is BrowserCurrentCustodyReadback
    with pytest.raises(ValueError, match="enrollment"):
        install_host_browser_original_enrollment(main.app, host)

    try:
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=main.app, client=("127.0.0.1", 8123)),
            base_url="http://127.0.0.1",
        ) as client:
            reply = await client.post(
                "/system/browser/custody/readback",
                headers={"Authorization": "Bearer " + _token()},
                json={
                    "request_id": case["record"].expected["request_id"],
                    "engagement_id": case["record"].expected["engagement_id"],
                },
            )
        assert reply.status_code == 200, reply.text[:200]
        answer = reply.json()
        assert answer["status"] == "CURRENT_ORIGINAL_CUSTODY_VERIFIED"
        assert answer["current_original_artifact_bytes_verified"] is True
        assert answer["independent_target_effect_verified"] is False
        assert answer["automatic_retry_authorized"] is False
        assert answer["production_release_certified"] is False
        assert set(answer["artifacts"]) == {"screenshot", "dom", "har"}
        assert "http_raw" not in answer["artifacts"]
        assert str(case["host_root"]) not in reply.text
        assert case["central_transport"].calls == 2
        assert case["native_transport"].calls == 2
        assert len(case["sign_events"]) == 1
        assert case["rows"]["action"]["status"] == "unknown"
    finally:
        delattr(main.app.state, _SLOT)


def test_host_installer_denies_unenrolled_or_api_supplied_service() -> None:
    assert not hasattr(main.app.state, _SLOT)
    with pytest.raises(ValueError, match="enrollment"):
        install_host_browser_original_enrollment(main.app, BrowserCurrentCustodyReadback())
    assert not hasattr(main.app.state, _SLOT)
