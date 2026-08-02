"""Chain Executor Agent

Takes exploit chains discovered by ChainComposerAgent, then executes them
hop-by-hop through the ExploitAgent facade (or directly via supplied
payloads), recording each validated link into the graph.
"""

import time
from typing import Any, Dict
from uuid import uuid4

import structlog

from ai_osop.agents.base import BaseAgent
from ai_osop.core import metrics_a2
from ai_osop.core.config import settings
from ai_osop.core.enums import AgentType
from ai_osop.core.models import Task

logger = structlog.get_logger(__name__)


class ChainExecutorAgent(BaseAgent):
    """Executes pre-computed exploit chains in order, treating each as a real task."""

    # Exploit delegate. Injected by the runtime; kept as `Any` so tests can stub a
    # facade without dragging the full ExploitAgent into scope.
    _exploit: Any = None

    # ValidationLedger injected by the runtime for hop-level lifecycle receipts.
    ledger: Any = None

    # ReceiptStore injected by the runtime (attribute assignment, per Part I
    # precedent in ExploitAgent). When set AND settings.evidence_receipts_enabled
    # is on, each attempted hop emits a best-effort ExploitReceipt carrying the
    # chain_id / hop_idx linkage plus the underlying facade receipt_id.
    receipt_store: Any = None

    async def _record_hop_receipt(
        self,
        task: Task,
        chain_id: str,
        idx: int,
        vuln_id: Any,
        validated: bool,
        result: Dict[str, Any],
        error: str = "",
    ) -> None:
        """Best-effort per-hop ExploitReceipt. Never flips the hop verdict."""
        if getattr(self, "receipt_store", None) is None:
            return
        if not settings.evidence_receipts_enabled:
            return
        try:
            from ai_osop.evidence.models import ExploitReceipt

            note = error or str(result.get("note", ""))
            hop_receipt = ExploitReceipt(
                receipt_id=f"rcpt-{uuid4().hex[:12]}",
                engagement_id=task.engagement_id,
                vuln_id=vuln_id or "hop-unknown",
                approval_id=task.payload.get("approval_id", "chain-auto"),
                hop_idx=idx,
                chain_id=chain_id,
                verdict="confirmed" if validated else "not_confirmed",
                confidence=float(result.get("confidence", 0.0) or 0.0),
                confirmation_note=note[:200],
                oracle_signals={"underlying_receipt": result.get("receipt_id")},
            )
            await self.receipt_store.record(hop_receipt)
        except Exception as e:  # noqa: BLE001
            logger.warning("hop_receipt_failed", hop=idx, error=str(e))

    @property
    def agent_type(self) -> AgentType:
        return AgentType.ATTACK_CHAIN

    def supports_task_type(self, task_type: str) -> bool:
        return task_type in {"execute_exploit_chain", "execute_chain_hop"}

    async def _setup_resources(self) -> None:
        # Expect _exploit to be assigned externally.
        pass

    async def _execute(self, task: Task) -> Dict[str, Any]:
        engagement_id = task.engagement_id
        chains = await self.ctx.graph_memory.find_vulnerability_chains(engagement_id)
        if not chains:
            return {"status": "done", "chain_run": [], "message": "no chains"}

        chain_id = str(task.payload.get("chain_id") or chains[0].get("id") or f"chain-{task.id}")
        chain_run = []
        with metrics_a2.time_chain_execution(chain_id):
            for chain in chains:
                hops = chain.get("nodes", [])
                for idx, hop in enumerate(hops):
                    url = hop.get("url")
                    vuln = hop.get("vuln") or {}
                    vuln_id = vuln.get("id")
                    payload = dict(vuln.get("payload", {}))
                    auth = task.payload.get("foothold_auth")
                    if auth:
                        payload.setdefault("auth", auth)
                    if url is None:
                        continue
                    hop_started = time.time()
                    try:
                        result = await self._exploit.validate_exploit(
                            endpoint=url,
                            vuln_class=vuln.get("type", "sqli"),
                            payload=payload,
                        )
                        metrics_a2.chain_steps_executed(1, chain_id)
                        if self.ledger is not None and vuln_id:
                            try:
                                await self.ledger.transition(
                                    vuln_id, "chain_executed", reason="hop executed"
                                )
                            except Exception as ledger_err:  # noqa: BLE001
                                logger.warning(
                                    "ledger_transition_failed",
                                    vuln_id=vuln_id,
                                    error=str(ledger_err),
                                )
                        chain_run.append(
                            {
                                "endpoint": url,
                                "vuln_id": vuln_id,
                                "validated": bool(result.get("validated", False)),
                                "result": result,
                            }
                        )
                        await self._record_hop_receipt(
                            task,
                            chain_id,
                            idx,
                            vuln_id,
                            bool(result.get("validated", False)),
                            result,
                        )
                        # Fail-fast: a broken hop invalidates the rest of the chain
                        # (later hops depend on the earlier foothold). Abort now and
                        # surface where the chain broke instead of spraying payloads
                        # at downstream endpoints under a false premise.
                        if not bool(result.get("validated", False)):
                            return {
                                "status": "chain_failed",
                                "chain_run": chain_run,
                                "aborted_at_hop": idx,
                                "chain_id": chain_id,
                            }
                    except Exception as e:  # noqa: BLE001
                        if self.ledger is not None and vuln_id:
                            try:
                                await self.ledger.transition(vuln_id, "chain_failed", reason=str(e))
                            except Exception as ledger_err:  # noqa: BLE001
                                logger.warning(
                                    "ledger_transition_failed",
                                    vuln_id=vuln_id,
                                    error=str(ledger_err),
                                )
                        chain_run.append(
                            {
                                "endpoint": url,
                                "vuln_id": vuln_id,
                                "validated": False,
                                "error": str(e),
                            }
                        )
                        await self._record_hop_receipt(
                            task, chain_id, idx, vuln_id, False, {}, error=str(e)
                        )
                        return {
                            "status": "chain_failed",
                            "chain_run": chain_run,
                            "aborted_at_hop": idx,
                            "chain_id": chain_id,
                        }
                    finally:
                        metrics_a2.chain_hop_seconds(time.time() - hop_started, chain_id, str(idx))
        if chain_run and all(entry.get("validated") for entry in chain_run if "validated" in entry):
            metrics_a2.chain_success(chain_id, len(chain_run))
        return {"status": "success", "chain_run": chain_run, "chain_id": chain_id}

    async def _cleanup_resources(self) -> None:
        pass
