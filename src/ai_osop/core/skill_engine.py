import json
import logging
import os
import tempfile
import threading
import time
from datetime import datetime
from typing import Any, Dict, List, Optional

import yaml

logger = logging.getLogger(__name__)


class SkillEngine:
    # Persisted counter fields (AIOSOP-AUDIT-2026-06-16). The skill bodies come from
    # the .md files; only these mutable stats are saved so reputation/effectiveness
    # survive restarts instead of resetting to zero every process.
    _STAT_FIELDS = (
        "usage_count",
        "hypothesis_count",
        "validation_count",
        "verified_findings",
        "accepted_findings",
        "total_payout",
        "total_cost",
    )

    def __init__(self, skills_dir: str, llm_client=None, stats_path: Optional[str] = None):
        self.skills_dir = skills_dir
        self.llm_client = llm_client
        self.skills: Dict[str, Dict[str, Any]] = {}
        self.execution_log: List[Dict[str, Any]] = []
        # Serialize concurrent stat saves so multiple agents cannot collide on the
        # temp file during the write→replace swap (AIOSOP-SKILLSTATS-001).
        self._save_lock = threading.Lock()
        # Durable stats path: deterministic from skills_dir (CWD-independent),
        # overridable via arg or OSOP_SKILL_STATS_PATH.
        self.stats_path = (
            stats_path
            or os.environ.get("OSOP_SKILL_STATS_PATH")
            or os.path.normpath(os.path.join(skills_dir, os.pardir, ".skill_stats.json"))
        )
        self._load_and_index_skills()
        self._load_stats()

    def _load_stats(self) -> None:
        """Merge persisted per-skill counters + execution log back into memory."""
        try:
            if not os.path.exists(self.stats_path):
                return
            with open(self.stats_path, "r", encoding="utf-8") as f:
                data = json.load(f)
        except Exception as e:
            logger.warning(f"Could not load skill stats from {self.stats_path}: {e}")
            return
        for sid, counters in (data.get("skills") or {}).items():
            if sid in self.skills and isinstance(counters, dict):
                for field in self._STAT_FIELDS:
                    if field in counters:
                        self.skills[sid][field] = counters[field]
        log = data.get("execution_log")
        if isinstance(log, list):
            self.execution_log = log[-1000:]

    def _save_stats(self) -> None:
        """Atomically persist per-skill counters + recent execution log.

        Hardened for AIOSOP-SKILLSTATS-001 (2026-07-03): the previous version wrote
        to a single fixed ``<stats>.tmp`` path shared by every writer. Under the live
        API, many agents trigger a save on each skill execution, so concurrent savers
        collided on that one temp file — on Windows the loser of the race sees the
        winner's handle and os.replace raises WinError 5 (Access Denied). The
        OneDrive-synced destination compounds this with transient external locks.
        Because the failure was caught and only logged at WARNING, skill stats
        silently stopped persisting, degrading the learning brain.

        Fix: (1) a UNIQUE temp file per write in the target directory, (2) a lock so
        two savers never overlap, (3) a bounded retry on the atomic swap to ride out
        transient OneDrive/AV/indexer locks, and (4) always clean up the temp file.
        """
        payload = {
            "skills": {
                sid: {field: skill.get(field, 0) for field in self._STAT_FIELDS}
                for sid, skill in self.skills.items()
                if skill.get("usage_count", 0)
                or skill.get("verified_findings", 0)
                or skill.get("accepted_findings", 0)
            },
            "execution_log": self.execution_log[-1000:],
        }
        target = self.stats_path
        directory = os.path.dirname(target) or "."
        with self._save_lock:
            tmp: Optional[str] = None
            try:
                os.makedirs(directory, exist_ok=True)
                fd, tmp = tempfile.mkstemp(
                    dir=directory, prefix=".skill_stats.", suffix=".tmp"
                )
                with os.fdopen(fd, "w", encoding="utf-8") as f:
                    json.dump(payload, f)
                last_err: Optional[Exception] = None
                for attempt in range(5):
                    try:
                        os.replace(tmp, target)
                        tmp = None  # ownership transferred; nothing to clean up
                        break
                    except PermissionError as e:
                        # OneDrive/AV/indexer may briefly hold the destination handle.
                        last_err = e
                        time.sleep(0.05 * (attempt + 1))
                else:
                    if last_err is not None:
                        raise last_err
            except Exception as e:
                logger.warning(f"Could not save skill stats to {target}: {e}")
            finally:
                if tmp and os.path.exists(tmp):
                    try:
                        os.remove(tmp)
                    except OSError:
                        pass

    def resolve_ids(self, ids: List[str]) -> List[str]:
        """Map a list of requested skill ids to REAL loaded skill ids, substituting
        any unknown id with the closest match via tag search (AIOSOP-AUDIT-2026-06-16).
        Fixes dead TASK_SKILL_MAP ids (e.g. rce/lfi/xxe/forensics/threat_hunting)
        generically — present and future — instead of failing silently."""
        out: List[str] = []
        seen = set()
        for sid in ids:
            real = sid
            if sid not in self.skills:
                q = sid.replace("_", " ").replace("-", " ")
                hits = self.tag_search(q, top_k=1)
                real = None
                if hits:
                    cand = hits[0]
                    terms = set(q.lower().split())
                    hay = (
                        set(
                            str(cand.get("id", ""))
                            .lower()
                            .replace("_", " ")
                            .replace("-", " ")
                            .split()
                        )
                        | set(str(t).lower() for t in (cand.get("tags") or []))
                        | set(str(cand.get("name", "")).lower().replace("-", " ").split())
                    )
                    if terms & hay:  # only substitute on a real term overlap
                        real = cand["id"]
            if real and real not in seen:
                seen.add(real)
                out.append(real)
        return out

    def _load_and_index_skills(self):
        if not os.path.exists(self.skills_dir):
            logger.warning(f"Skills directory not found: {self.skills_dir}")
            return

        for filename in os.listdir(self.skills_dir):
            if not filename.endswith(".md"):
                continue
            filepath = os.path.join(self.skills_dir, filename)
            try:
                with open(filepath, "r", encoding="utf-8") as f:
                    content = f.read()

                frontmatter = {}
                body = content
                if content.startswith("---"):
                    parts = content.split("---", 2)
                    if len(parts) >= 3:
                        try:
                            frontmatter = yaml.safe_load(parts[1]) or {}
                            body = parts[2].strip()
                        except yaml.YAMLError as ye:
                            logger.error(f"Error parsing YAML in {filename}: {ye}")

                skill_id = filename[:-3]
                self.skills[skill_id] = {
                    "id": skill_id,
                    "name": frontmatter.get("name", skill_id),
                    "description": frontmatter.get("description", ""),
                    "tags": frontmatter.get("tags", []),
                    "author": frontmatter.get("author", "unknown"),
                    "body": body,
                    "raw_content": content,
                    "usage_count": 0,
                    "hypothesis_count": 0,
                    "validation_count": 0,
                    "verified_findings": 0,
                    "accepted_findings": 0,
                    "total_payout": 0.0,
                    "total_cost": 0.0,
                    "embedding": None,
                }
            except Exception as e:
                logger.error(f"Failed to load skill {filename}: {e}")

        self.playbooks: Dict[str, Dict[str, Any]] = {
            "api_recon_to_idor": {
                "name": "API Recon → IDOR Chain",
                "skill_ids": ["recon", "api_security", "idor_testing"],
                "reputation": 0.0,
                "verified_findings": 0,
                "total_payout": 0.0,
            }
        }

    async def get_embedding(self, text: str):
        if not self.llm_client:
            return None
        try:
            return await self.llm_client.get_embedding(text)
        except Exception:
            return None

    async def semantic_search(self, query: str, top_k: int = 3) -> List[Dict[str, Any]]:
        query_emb = await self.get_embedding(query)
        if not query_emb:
            return self.tag_search(query, top_k)

        import numpy as np

        scores = []
        for sid, skill in self.skills.items():
            if skill["embedding"] is None:
                text_to_embed = f"{skill['name']} {skill['description']} {' '.join(str(t) for t in skill['tags'])}"
                skill["embedding"] = await self.get_embedding(text_to_embed)

            if skill["embedding"]:
                sim = np.dot(query_emb, skill["embedding"]) / (
                    np.linalg.norm(query_emb) * np.linalg.norm(skill["embedding"])
                )
                scores.append((sim, skill))
            else:
                scores.append((-1, skill))

        scores.sort(key=lambda x: x[0], reverse=True)
        return [s[1] for s in scores[:top_k]]

    def tag_search(self, query: str, top_k: int = 3) -> List[Dict[str, Any]]:
        query_terms = set(query.lower().replace("-", " ").replace("_", " ").split())
        scores = []
        for sid, skill in self.skills.items():
            # Tags can come from YAML frontmatter as ints/floats/None — coerce to
            # str before lowercasing, otherwise tag_search crashes on real skills.
            tags = set(str(t).lower() for t in (skill.get("tags") or []))
            desc_terms = set(str(skill.get("description") or "").lower().split())
            name_terms = set(str(skill.get("name") or "").lower().replace("-", " ").split())

            score = (
                len(query_terms.intersection(tags)) * 3
                + len(query_terms.intersection(name_terms)) * 2
                + len(query_terms.intersection(desc_terms))
            )
            scores.append((score, skill))

        scores.sort(key=lambda x: x[0], reverse=True)
        return [s[1] for s in scores[:top_k]]

    async def rank_and_select(
        self, task_type: str, context: str, agent_id: str, top_k: int = 3
    ) -> List[Dict[str, Any]]:
        # Semantic search using context and task_type
        search_query = f"{task_type} {context[:200]}"
        return await self.semantic_search(search_query, top_k=top_k)

    def get_skill(self, skill_id: str) -> Optional[Dict[str, Any]]:
        return self.skills.get(skill_id)

    def record_execution(
        self,
        skill_id: str,
        agent_id: str,
        reason: str,
        stage: str = "execution",
        finding_id: Optional[str] = None,
        cost: float = 0.0,
        payout: float = 0.0,
        accepted: bool = False,
    ):
        """
        stage: execution | hypothesis | validation | verification | acceptance
        """
        if skill_id in self.skills:
            if stage == "execution":
                self.skills[skill_id]["usage_count"] += 1
                self.skills[skill_id]["total_cost"] += cost
            elif stage == "hypothesis":
                self.skills[skill_id]["hypothesis_count"] += 1
            elif stage == "validation":
                self.skills[skill_id]["validation_count"] += 1
            elif stage == "verification":
                self.skills[skill_id]["verified_findings"] += 1
            elif stage == "acceptance":
                self.skills[skill_id]["accepted_findings"] += 1
                self.skills[skill_id]["total_payout"] += payout

        self.execution_log.append(
            {
                "timestamp": datetime.utcnow().isoformat(),
                "skill_id": skill_id,
                "agent_id": agent_id,
                "reason": reason,
                "stage": stage,
                "finding_id": finding_id,
                "payout": payout,
                "accepted": accepted,
            }
        )

        # Durable: persist so usage/reputation survive restarts (AIOSOP-AUDIT-2026-06-16).
        self._save_stats()

    def get_skill_effectiveness(self, skill_id: str) -> float:
        """Returns the ratio of verified findings to total executions."""
        skill = self.skills.get(skill_id)
        if not skill or skill["usage_count"] == 0:
            return 0.0
        return skill["verified_findings"] / skill["usage_count"]

    def get_skill_reputation(self, skill_id: str) -> float:
        """
        Holistic Reputation Score (0.0 - 10.0)
        Factors:
        - Acceptance Rate (Accepted / Verified)
        - Revenue ROI (Payout / Cost)
        - Findings Density (Verified / Activations)
        """
        skill = self.skills.get(skill_id)
        if not skill or skill["usage_count"] == 0:
            return 0.0

        acceptance_rate = (
            (skill["accepted_findings"] / skill["verified_findings"])
            if skill["verified_findings"] > 0
            else 0
        )
        roi = skill["total_payout"] / (skill["total_cost"] + 0.1)  # Avoid div by zero
        density = skill["verified_findings"] / skill["usage_count"]

        # Reputation is a weighted blend
        reputation = (acceptance_rate * 4.0) + (min(2.0, roi) * 2.0) + (density * 4.0)
        return round(min(10.0, reputation), 2)

    def get_stats(self):
        loaded = len(self.skills)
        activated = len(
            set(log["skill_id"] for log in self.execution_log if log["stage"] == "execution")
        )

        sorted_skills = sorted(
            self.skills.values(), key=lambda x: self.get_skill_reputation(x["id"]), reverse=True
        )
        top_skills = [
            {
                "id": s["id"],
                "name": s["name"],
                "usage": s["usage_count"],
                "reputation": self.get_skill_reputation(s["id"]),
                "revenue_roi": s["total_payout"] / (s["total_cost"] + 0.1),
                "acceptance_rate": (
                    (s["accepted_findings"] / s["verified_findings"])
                    if s["verified_findings"] > 0
                    else 0
                ),
                "total_payout": s["total_payout"],
            }
            for s in sorted_skills[:10]
            if s["usage_count"] > 0
        ]

        total_payout = sum(s["total_payout"] for s in self.skills.values())
        total_cost = sum(s["total_cost"] for s in self.skills.values())

        return {
            "loaded_skills": loaded,
            "activated_skills": activated,
            "top_skills": top_skills,
            "total_revenue": total_payout,
            "revenue_roi": total_payout / (total_cost + 0.1),
            "findings_contributed": sum(s["verified_findings"] for s in self.skills.values()),
            "recent_executions": self.execution_log[-50:][::-1],
        }
