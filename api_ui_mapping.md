# API Surface Audit (api_ui_mapping.md)

This report maps the backend API endpoints to their corresponding frontend utilization.

---

| API Endpoint | Method | Frontend Used? | Component / Page | Status |
|---|---|---|---|---|
| `/engagements` | GET | Yes | `AuthAudit.tsx`, `ResearchIntelligence.tsx`, `SkillIntelligence.tsx` | Used |
| `/engagements` | POST | Yes | `NewMissionModal.tsx` | Used |
| `/engagements/{id}` | GET | Yes | `MissionReport.tsx` | Used |
| `/engagements/{id}/transition`| POST | No | - | **Missing UI** |
| `/engagements/{id}/halt` | POST | No | - | **Missing UI** |
| `/engagements/{id}/findings` | GET | Yes | `AuthAudit.tsx` | Used |
| `/engagements/{id}/findings/{fid}/vault`| GET | Yes | `FindingsVerification.tsx` | Used |
| `/engagements/{id}/findings/{fid}/verify`| POST | Yes | `FindingsVerification.tsx` | Used |
| `/engagements/{id}/findings/{fid}/replay`| POST | Yes | `FindingsVerification.tsx`, `DifferentialAuth.tsx` | Used |
| `/engagements/{id}/poc/generate` | POST | Yes | `ResearchIntelligence.tsx` | Used |
| `/engagements/{id}/workflows/{wid}/replay`| POST | Yes | `ResearchIntelligence.tsx` | Used |
| `/system/skills/stats` | GET | Yes | `SkillIntelligence.tsx` | Used |
| `/system/config` | GET | No | - | **Missing UI** |
| `/system/sandbox/status` | GET | No | - | **Missing UI** |
| `/system/mcp/health` | GET | No | - | **Missing UI** |
| `/system/dlq/stats` | GET | No | - | **Missing UI** |
| `/system/dlq/entries` | GET | No | - | **Missing UI** |
| `/system/dlq/requeue` | POST | No | - | **Missing UI** |
| `/system/dlq/discard` | POST | No | - | **Missing UI** |
| `/approvals/pending` | GET | Yes | `Administration.tsx` | Used |
| `/approvals/{id}` | GET | Yes | `Administration.tsx` | Used |
| `/approvals/{id}/resolve` | POST | Yes | `Administration.tsx` | Used |

---

## Summary
*   **API Coverage**: Most findings and engagement lifecycle endpoints are used.
*   **Infrastructure Gaps**: All `/system/*` endpoints are currently unexposed in the UI.
*   **Missing Workflows**: Transitioning phases (`/transition`) and emergency halting (`/halt`) engagements are entirely missing from the frontend, leaving operators unable to control engagement lifecycles via the dashboard.
