"""Adversarial raw-JSON consent/CAS checks; no application database used."""

import json

import pytest

from tests.test_flow_resource_folders_20261019 import FID, _query, env


@pytest.mark.parametrize(
    "payload",
    [
        '{"operation":"create","operation":"delete","name":"notes",'
        '"expected_catalog_revision":0,"explicit_human_confirmation":true}',
        '{"operation":"create","name":"notes","expected_catalog_revision":0,'
        '"expected_catalog_revision":1,"explicit_human_confirmation":true}',
        '{"operation":"create","name":"notes","expected_catalog_revision":0,'
        '"explicit_human_confirmation":false,"explicit_human_confirmation":true}',
        '{"operation":"create","name":"notes","expected_catalog_revision":0,'
        '"explicit_human_confirmation":true,"unexpected_secret":"denied"}',
        '{"operation":"create","name":"notes","expected_catalog_revision":false,'
        '"explicit_human_confirmation":true}',
    ],
)
def test_duplicate_consent_or_cas_and_extra_fields_never_write(env, payload):
    response = env.client.post(
        f"/flows/{FID}/resource-folders",
        params=_query(env),
        headers={**env.headers, "content-type": "application/json"},
        content=payload,
    )
    assert response.status_code == 422, response.text
    assert env.db.catalog is None and not env.db.events


def test_oversized_json_never_reaches_durable_metadata(env):
    response = env.client.post(
        f"/flows/{FID}/resource-folders",
        params=_query(env),
        headers={**env.headers, "content-type": "application/json"},
        content=json.dumps(
            {
                "operation": "create",
                "name": "notes",
                "expected_catalog_revision": 0,
                "explicit_human_confirmation": True,
                "padding": "x" * 3000,
            }
        ),
    )
    assert response.status_code == 413
    assert env.db.catalog is None


def test_wrong_content_type_is_not_accepted_as_signed_mutation(env):
    response = env.client.post(
        f"/flows/{FID}/resource-folders",
        params=_query(env),
        headers={**env.headers, "content-type": "text/plain"},
        content='{"operation":"create","name":"notes","expected_catalog_revision":0,'
        '"explicit_human_confirmation":true}',
    )
    assert response.status_code == 415
    assert env.db.catalog is None
