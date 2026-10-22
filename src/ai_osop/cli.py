"""
AI-OSOP CLI Interface
Command-line interface for operators to manage engagements,
agents, and view results.
"""

import json
from pathlib import Path
from typing import Any, Optional

import click
import httpx

API_BASE = "http://localhost:8200"


@click.group()
@click.option("--api-url", default="http://localhost:8200", help="AI-OSOP API URL")
@click.option("--token", envvar="OSOP_TOKEN", help="API authentication token")
@click.pass_context
def cli(ctx: click.Context, api_url: str, token: Optional[str]) -> None:
    """AI-OSOP Command Line Interface"""
    ctx.ensure_object(dict)
    ctx.obj["api_url"] = api_url
    ctx.obj["token"] = token


@cli.group()
def engagement() -> None:
    """Manage penetration testing engagements"""
    pass


@engagement.command("create")
@click.argument("engagement_id")
@click.option("--domain", multiple=True, help="Must match the signed target domains")
@click.option("--ip", multiple=True, help="Target IP ranges")
@click.option("--exclude", multiple=True, help="Excluded targets")
@click.option("--approval-for", multiple=True, help="Must match the signed approval policy")
@click.option(
    "--signed-roe",
    required=True,
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    help="Signed ROE JSON envelope",
)
@click.pass_context
def create_engagement(
    ctx: click.Context,
    engagement_id: str,
    domain: tuple[str, ...],
    ip: tuple[str, ...],
    exclude: tuple[str, ...],
    approval_for: tuple[str, ...],
    signed_roe: Path,
) -> None:
    """Create a new engagement"""
    try:
        with signed_roe.open("rb") as stream:
            raw = stream.read(262145)
        if len(raw) > 262144:
            raise ValueError("Envelope exceeds limit")
        envelope = json.loads(raw, object_pairs_hook=_unique_json_object)
        policy = envelope["policy"]
        if policy["engagement_id"] != engagement_id:
            raise ValueError("Engagement ID must match signed policy")
        for supplied, field in (
            (domain, "domains"),
            (ip, "ips"),
            (exclude, "exclusions"),
            (approval_for, "approval_required_for"),
        ):
            if supplied and list(supplied) != policy[field]:
                raise ValueError("Options must match signed policy")
        fields = (
            "engagement_id",
            "domains",
            "ips",
            "exclusions",
            "allowed_techniques",
            "restrictions",
            "approval_required_for",
            "testing_window_start",
            "testing_window_end",
            "roe",
        )
        payload = {field: policy[field] for field in fields}
        payload.update(authorization_ref=policy["authorization_id"], signed_roe=envelope)
        from ai_osop.api.deps import CreateEngagementRequest

        payload = CreateEngagementRequest(**payload).model_dump(mode="json")
    except (OSError, ValueError, TypeError, KeyError) as exc:
        raise click.ClickException("Invalid signed ROE envelope or mismatched options") from exc
    data = _api_request(ctx, "POST", "/engagements", json=payload)
    click.echo(f"Engagement created: {data['session_id']}")
    click.echo(f"Phase: {data['phase']}")


@engagement.command("list")
@click.pass_context
def list_engagements(ctx: click.Context) -> None:
    """List active engagements"""
    data = _api_request(ctx, "GET", "/engagements")
    click.echo("Active engagements:")
    for entry in data:
        click.echo(f"  {entry['session_id']} {entry['phase']}")


def _api_request(ctx: click.Context, method: str, path: str, **kwargs: Any) -> Any:
    if not ctx.obj.get("token"):
        raise click.ClickException("Operator authentication token is required")
    try:
        response = httpx.request(
            method,
            f"{ctx.obj['api_url']}{path}",
            headers={"Authorization": f"Bearer {ctx.obj['token']}"},
            timeout=30.0,
            **kwargs,
        )
        if not 200 <= response.status_code < 300:
            raise click.ClickException(f"API request rejected (HTTP {response.status_code})")
        return response.json()
    except (httpx.HTTPError, ValueError) as exc:
        raise click.ClickException("API response unavailable or invalid") from exc


def _unique_json_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate envelope field")
        result[key] = value
    return result


@engagement.command("halt")
@click.argument("session_id")
@click.option("--reason", default="Operator request", help="Halt reason")
@click.pass_context
def halt_engagement(ctx: click.Context, session_id: str, reason: str) -> None:
    """Emergency halt an engagement"""
    _api_request(ctx, "POST", f"/engagements/{session_id}/halt", params={"reason": reason})
    click.echo(f"Engagement {session_id} halted")


@cli.group()
def task() -> None:
    """Manage tasks"""
    pass


@task.command("create")
@click.option("--type", required=True, help="Task type")
@click.option("--agent-type", required=True, help="Agent type (recon, vuln_analysis, etc.)")
@click.option("--engagement", required=True, help="Engagement ID")
@click.option("--priority", default=5, type=int, help="Task priority (1-10)")
@click.option("--payload", help="Task payload as JSON string")
@click.pass_context
def create_task(
    ctx: click.Context,
    type: str,
    agent_type: str,
    engagement: str,
    priority: int,
    payload: Optional[str],
) -> None:
    """Create and schedule a task"""
    task_payload = {
        "task_type": type,
        "agent_type": agent_type,
        "engagement_id": engagement,
        "priority": priority,
        "payload": json.loads(payload) if payload else {},
    }

    data = _api_request(ctx, "POST", "/tasks", json=task_payload)
    click.echo(f"Task created: {data['id']}")


@cli.group()
def agent() -> None:
    """Manage agents"""
    pass


@agent.command("list")
@click.pass_context
def list_agents(ctx: click.Context) -> None:
    """List all agents"""
    agents = _api_request(ctx, "GET", "/agents")
    click.echo(f"{'Agent ID':<20} {'Type':<20} {'Status':<10} {'Task':<30}")
    click.echo("-" * 80)
    for a in agents:
        click.echo(
            f"{a['agent_id']:<20} {a['agent_type']:<20} {a['status']:<10} {str(a.get('current_task')):<30}"
        )


@cli.group()
def approval() -> None:
    """Manage approval requests"""
    pass


@approval.command("list")
@click.pass_context
def list_approvals(ctx: click.Context) -> None:
    """List pending approvals"""
    approvals = _api_request(ctx, "GET", "/approvals/pending")
    if not approvals:
        click.echo("No pending approvals")
        return
    click.echo(f"{'Request ID':<20} {'Action':<20} {'Target':<30}")
    for a in approvals:
        click.echo(f"{a['id']:<20} {a['action_type']:<20} {a['target']:<30}")


@approval.command("resolve")
@click.argument("request_id")
@click.argument("decision", type=click.Choice(["approved", "rejected", "modified"]))
@click.option("--operator-id", default="operator-1", help="Operator ID")
@click.option("--notes", help="Decision notes")
@click.pass_context
def resolve_approval(
    ctx: click.Context, request_id: str, decision: str, operator_id: str, notes: Optional[str]
) -> None:
    """Resolve an approval request"""
    payload = {
        "request_id": request_id,
        "decision": decision,
        "operator_id": operator_id,
        "notes": notes,
    }

    _api_request(ctx, "POST", f"/approvals/{request_id}/resolve", json=payload)
    click.echo(f"Approval {request_id} {decision}")


def main() -> None:
    cli()


if __name__ == "__main__":
    main()
