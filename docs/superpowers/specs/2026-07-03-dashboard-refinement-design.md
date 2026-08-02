# AI-OSOP Dashboard Refinement — Design

**Date:** 2026-07-03
**Status:** Proposed (awaiting review)
**Scope:** Frontend only (`ui/`). No backend, API, or data-contract changes.

## Goal

Evolve the existing AI-OSOP dashboard into a polished, enterprise-grade cybersecurity
platform by **refining execution**, not rebuilding. Preserve all working features, the
backend integration, and the product's distinctive "neon terminal / cyberpunk SOC"
identity. No mock data. No regressions.

## Direction Decisions (locked)

1. **Refine the neon identity.** Keep the cyberpunk-SOC soul; fix execution. Lowest
   regression risk and honors the "improve, don't rebuild" mandate.
2. **Full scope, autonomous sweep.** All six phases below; proceed page-by-page,
   verifying each against the live app, checking in at phase boundaries.
3. **Green leads.** Neon green is brand/primary/operational-success; cyan is the
   secondary interactive/active/live accent; red is critical/alert. Amber is added
   for warning/medium severity (currently missing).

## Root-Cause Findings (evidence)

- **Dual conflicting palette.** `styles.css :root` defines a neon-green system
  (`--primary-fixed:#39ff14`, cyan, red); `tailwind.config.js` defines a *different*
  teal/mint system (`primary-fixed:#24ffcd`, `primary-container:#00ffcc`). The same
  class name (`text-primary-fixed`) resolves to green or teal depending on whether a
  hand-written rule or a Tailwind-generated rule wins on source order. Cause of
  page-to-page color drift.
- **Duplicated utility layer.** `styles.css` hand-rolls ~150 lines of `.flex`,
  `.grid-cols-2`, `.p-4`, etc. that Tailwind 4 already generates — dead weight that
  also fights Tailwind on specificity.
- **Pervasive micro-typography.** 22 files use `text-[8px]`/`[9px]`/`[10px]`; worst:
  RealityVerificationCenter (20), FindingsVerification (19), Overview (14). Plus inline
  `style={{fontSize}}` overrides bypassing the type scale. Readability/contrast problem.
- **No shared primitive layer.** Only `Card` is shared. Even well-built helpers
  (`KpiTile`, `StatusPill`) live *inside* `Overview`; other pages inline their own
  stat/table/badge markup → visual drift and duplication.
- **Loading/empty/error not first-class.** Only 3 of 17 pages reference any loading
  state; most render straight from stores, so pre-hydration they silently show zeros
  instead of skeletons. Only an app-level `ErrorBoundary` exists.

## The Design

### Phase 1 — One source of truth for design tokens

Collapse the two palettes into a single canonical system defined as CSS variables in
`:root`, and change `tailwind.config.js` color values to reference those variables
(`'primary-fixed': 'var(--primary-fixed)'`, …). After this, a class name and a CSS
variable can never disagree again — the highest-leverage fix, correcting drift on every
page at once.

Canonical tokens (roles → value):

- `--primary` / brand·operational·success — neon green `#39ff14`
- `--primary-container` — deep green `#107100` (fills, active borders)
- `--secondary` / interactive·active·live — cyan `#00f1fd`
- `--secondary-container` — deep cyan `#004f53`
- `--critical` / critical·alert — red `#ff3131`
- `--warning` / warning·medium-severity — amber `#ffb020` (NEW)
- Surface ramp (kept): `#050506` → `#0a0a0b` → `#131314` → `#1a1a1d` → `#2a2a2d`
- Text: `--on-surface #e5e2e3`, `--on-surface-variant` (readable neutral, contrast-checked)

Severity ramp (for findings): critical = red, high = orange/amber-strong, medium =
amber, low = cyan-muted, info = neutral. Status ramp: verified = green, validated =
cyan, pending = neutral, rejected = muted/strikethrough.

The retired teal/mint values in `tailwind.config.js` are removed. The `borderRadius`
(sharp corners) and spacing tokens are kept — they are the identity.

### Phase 2 — Delete the duplicated utility layer

Remove the ~150 lines in `styles.css` that re-implement Tailwind utilities. **Keep** the
genuine custom effects that give the product its character: `hud-corners`, `reveal-up`,
`sweep-line`, `live-dot`, `glow-cyan/red/green`, `scanline`, `terminal-grid`,
`animate-pulse-neon`, and the keyframes. Verify no component depended on a hand-rolled
utility that Tailwind doesn't provide (Tailwind is a superset here).

### Phase 3 — Real type scale, kill micro-type

Adopt the existing named scale as the vocabulary and enforce an **11px floor** for mono
caps labels; body 12–14px. Replace `text-[8px]`/`[9px]`/`[10px]` and inline `fontSize`
with semantic classes (`font-label-caps`, `font-code-sm`, `font-body-md`,
`font-display-lg`, plus a single `label-xs` at 10px reserved for genuinely dense chrome
only). This is the biggest day-to-day felt improvement.

### Phase 4 — Shared primitive library

Extract a small vocabulary (promoted from patterns already in the codebase) into
`ui/src/components/shared/`:

- `StatTile` — from Overview's `KpiTile` (label, value, caption, accent, icon, meta).
- `StatusBadge` — from `StatusPill`, backed by the severity/status color map.
- `DataTable` — sticky header + rows + built-in empty state (from Overview's ledger).
- `Panel` — `Card` generalized (variants: default, inset, glow).
- `Skeleton`, `EmptyState`, `ErrorState` — first-class loading/empty/error primitives.
- `SectionHeader` — consistent page/section titling.

Each primitive: one clear purpose, typed props, no store coupling (data passed in).
Consistency becomes structural rather than per-page discipline.

### Phase 5 — Page-by-page sweep

For each of the 17 pages: replace inline markup with primitives, add loading/empty/error
states, fix spacing and micro-type, unify accents to their semantic roles. Data still
flows from the existing stores/services unchanged. Verified live per page before moving on.

### Phase 6 — Accessibility pass

Neon-on-black contrast audit (adjust `on-surface-variant` and muted states to meet
WCAG AA for body text where feasible), `focus-visible` rings on all interactive
elements, `aria-label`s on icon-only buttons, keyboard navigation for the sidebar and
the engagement selector, and reduced-motion honoring for the neon animations.

## Verification Strategy

After each phase: `tsc --noEmit` (relative to the known pre-existing baseline errors)
and `vite build`; then drive the live UI on `:5173` against the running API (PID 13548)
to confirm real data still flows and nothing regressed. The app is running now, which
makes verification tight and behavior-based rather than assumption-based.

## Non-Goals (YAGNI)

- No framework, router, or build-tool swap; no component-library adoption. Keep
  Tailwind 4 + custom effects.
- No new features, pages, or backend/data-contract changes.
- No mock data anywhere.
- Keep the sharp-cornered neon identity. We refine execution, not what the product *is*.

## Risks & Mitigations

- **Token remap changes colors subtly on many pages at once (Phase 1).** Mitigation:
  it's a single, reviewable diff; verify against live pages immediately; the change
  *removes* inconsistency rather than adding a new look.
- **A hidden dependence on a hand-rolled utility (Phase 2).** Mitigation: grep each
  removed class before deleting; build + live-check after.
- **Primitive extraction subtly alters a page's layout (Phase 4–5).** Mitigation:
  primitives are extracted from existing markup verbatim first, then applied; per-page
  live verification.

## Rollout

Feature branch off the current one; one focused commit per phase (and per page within
Phase 5) so any regression is trivially bisectable and revertible.
