"""Companion test for the ephemeral blind-sink fixture in conftest.py.

Proves that the sink registers an injected callback URL server-side and that
the callback later shows up in the captured-paths list (the blind-oracle seam
the receipts trading on out-of-band confirmation relies on).
"""

import asyncio

import httpx


async def test_blind_sink_records_callback(blind_sink_target):
    url, seen = blind_sink_target
    async with httpx.AsyncClient() as client:
        r = await client.get(f"{url}/inject?cb={url}/cb/tok-99", follow_redirects=False)
    assert r.status_code in (200, 302)
    await asyncio.sleep(0.05)
    assert any("/cb/tok-99" in p for p in seen)
