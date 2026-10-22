"""Actual mounted API must not expose 0042 originals without host enrollment.

These are routing/denial checks, not independent signer or database evidence.
"""

import pytest
from httpx import ASGITransport, AsyncClient

from tests.qualification.test_0039_mounted_reviewed_library_preflight_20261021 import (
    BODY,
    FLOW,
    isolated,
    token,
)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "suffix",
    (
        "store-reviewed-original",
        "store-reviewed-original/readback",
        "record-citation",
        "record-citation/readback",
    ),
)
async def test_mounted_original_paths_fail_closed_without_host_roots(isolated, suffix):
    path = f"/flows/{FLOW}/reviewed-library-import/{suffix}"
    assert any(getattr(route, "path", None) == "/flows/{flow_id}/reviewed-library-import/" + suffix
               for route in isolated.routes)
    async with AsyncClient(transport=ASGITransport(app=isolated), base_url="http://testserver") as client:
        response = await client.post(path, json=BODY, headers={"Authorization": "Bearer " + token()})
    assert response.status_code == 503
    assert "content" not in response.text.lower()
    assert response.headers.get("cache-control") == "private, no-store"

