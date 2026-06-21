"""
AI-OSOP CLI Interface
Command-line interface for operators to manage engagements,
agents, and view results.
"""

import asyncio
import json
import sys
from typing import Optional

import click
import httpx

API_BASE = "http://localhost:8200"


@click.group()
@click.option("--api-url", default="http://localhost:8200", help="AI-OSOP API URL")
@click.option("--token", envvar="OSOP_TOKEN", help="API authentication token")
@click.pass_context
def cli(ctx, api_url, token):
    """AI-OSOP Command Line Interface"""
    ctx.ensure_object(dict)
    ctx.obj["api_url"] = api_url
    ctx.obj["token"] = token


@cli.group()
def engagement():
    """Manage penetration testing engagements"""
    pass


@engagement.command("create")
@click.argument("engagement_id")
@click.option("--domain", multiple=True, required=True, help="Target domains")
@click.option("--ip", multiple=True, help="Target IP ranges")
@click.option("--exclude", multiple=True, help="Excluded targets")
@click.option("--approval-for", multiple=True, default=["rce", "sqli"], help="Require approval for")
@click.pass_context
def create_engagement(ctx, engagement_id, domain, ip, exclude, approval_for):
    """Create a new engagement"""
    payload = {
        "engagement_id": engagement_id,
        "domains": list(domain),
        "ips": list(ip),
        "exclusions": list(exclude),
        "approval_required_for": list(approval_for),
    }

    response = httpx.post(
        f"{ctx.obj['api_url']}/engagements",
        json=payload,
        headers={"Authorization": f"Bearer {ctx.obj['token']}"},
    )

    if response.status_code == 200:
        data = response.json()
        click.echo(f"Engagement created: {data['session_id']}")
        click.echo(f"Phase: {data['phase']}")
    else:
        click.echo(f"Error: {response.status_code} - {response.text}", err=True)


@engagement.command("list")
@click.pass_context
def list_engagements(ctx):
    """List active engagements"""
    # This would query the API for all engagements
    click.echo("Active engagements:")
    click.echo("  (Use API directly for full list)")


@engagement.command("halt")
@click.argument("session_id")
@click.option("--reason", default="Operator request", help="Halt reason")
@click.pass_context
def halt_engagement(ctx, session_id, reason):
    """Emergency halt an engagement"""
    response = httpx.post(
        f"{ctx.obj['api_url']}/engagements/{session_id}/halt",
        params={"reason": reason},
        headers={"Authorization": f"Bearer {ctx.obj['token']}"},
    )

    if response.status_code == 200:
        click.echo(f"Engagement {session_id} halted")
    else:
        click.echo(f"Error: {response.status_code}", err=True)


@cli.group()
def task():
    """Manage tasks"""
    pass


@task.command("create")
@click.option("--type", required=True, help="Task type")
@click.option("--agent-type", required=True, help="Agent type (recon, vuln_analysis, etc.)")
@click.option("--engagement", required=True, help="Engagement ID")
@click.option("--priority", default=5, type=int, help="Task priority (1-10)")
@click.option("--payload", help="Task payload as JSON string")
@click.pass_context
def create_task(ctx, type, agent_type, engagement, priority, payload):
    """Create and schedule a task"""
    task_payload = {
        "task_type": type,
        "agent_type": agent_type,
        "engagement_id": engagement,
        "priority": priority,
        "payload": json.loads(payload) if payload else {},
    }

    response = httpx.post(
        f"{ctx.obj['api_url']}/tasks",
        json=task_payload,
        headers={"Authorization": f"Bearer {ctx.obj['token']}"},
    )

    if response.status_code == 200:
        data = response.json()
        click.echo(f"Task created: {data['id']}")
    else:
        click.echo(f"Error: {response.status_code} - {response.text}", err=True)


@cli.group()
def agent():
    """Manage agents"""
    pass


@agent.command("list")
@click.pass_context
def list_agents(ctx):
    """List all agents"""
    response = httpx.get(
        f"{ctx.obj['api_url']}/agents", headers={"Authorization": f"Bearer {ctx.obj['token']}"}
    )

    if response.status_code == 200:
        agents = response.json()
        click.echo(f"{'Agent ID':<20} {'Type':<20} {'Status':<10} {'Task':<30}")
        click.echo("-" * 80)
        for a in agents:
            click.echo(
                f"{a['agent_id']:<20} {a['agent_type']:<20} {a['status']:<10} {a.get('current_task', 'None'):<30}"
            )
    else:
        click.echo(f"Error: {response.status_code}", err=True)


@cli.group()
def approval():
    """Manage approval requests"""
    pass


@approval.command("list")
@click.pass_context
def list_approvals(ctx):
    """List pending approvals"""
    response = httpx.get(
        f"{ctx.obj['api_url']}/approvals/pending",
        headers={"Authorization": f"Bearer {ctx.obj['token']}"},
    )

    if response.status_code == 200:
        approvals = response.json()
        if not approvals:
            click.echo("No pending approvals")
            return

        click.echo(f"{'Request ID':<20} {'Action':<20} {'Target':<30} {'Risk':<10}")
        click.echo("-" * 80)
        for a in approvals:
            click.echo(f"{a['id']:<20} {a['action_type']:<20} {a['target']:<30} {'HIGH':<10}")
    else:
        click.echo(f"Error: {response.status_code}", err=True)


@approval.command("resolve")
@click.argument("request_id")
@click.argument("decision", type=click.Choice(["approved", "rejected", "modified"]))
@click.option("--operator-id", default="operator-1", help="Operator ID")
@click.option("--notes", help="Decision notes")
@click.pass_context
def resolve_approval(ctx, request_id, decision, operator_id, notes):
    """Resolve an approval request"""
    payload = {
        "request_id": request_id,
        "decision": decision,
        "operator_id": operator_id,
        "notes": notes,
    }

    response = httpx.post(
        f"{ctx.obj['api_url']}/approvals/{request_id}/resolve",
        json=payload,
        headers={"Authorization": f"Bearer {ctx.obj['token']}"},
    )

    if response.status_code == 200:
        click.echo(f"Approval {request_id} {decision}")
    else:
        click.echo(f"Error: {response.status_code} - {response.text}", err=True)


def main():
    cli()


if __name__ == "__main__":
    main()
