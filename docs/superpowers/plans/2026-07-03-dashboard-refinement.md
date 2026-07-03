# AI-OSOP Dashboard Refinement Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Refine the existing AI-OSOP dashboard (`ui/`) into an enterprise-grade cybersecurity UI by fixing foundational execution defects and extracting a shared component vocabulary — without rebuilding, changing behavior, or introducing mock data.

**Architecture:** Fix root causes once at the foundation (unified CSS-variable-backed design tokens, delete the Tailwind-duplicating utility layer, real type scale), extract a small primitive library promoted from patterns already in the codebase, then sweep all pages to consume it. Each task is independently committable and verified live against the running app.

**Tech Stack:** React 19, Vite 7, Tailwind CSS 4 (PostCSS plugin + `@config`), zustand 5, react-router 7, recharts 3, `@xyflow/react` 12, lucide-react.

## Global Constraints

- Frontend only. No files outside `ui/` are modified. No backend, API, route, or data-contract changes.
- No mock/placeholder data. All data continues to flow from existing stores (`useSwarmStore`, `useIntelligenceStore`) and `services/`.
- No new runtime dependencies. Tailwind + custom CSS effects only; no component library.
- Keep the sharp-cornered neon identity: `borderRadius` DEFAULT stays `0`; custom effects (`hud-corners`, `reveal-up`, `glow-*`, `scanline`, `terminal-grid`, `live-dot`, `sweep-line`, `animate-pulse-neon`) are preserved.
- Accent roles are fixed: green `#39ff14` = brand/primary/operational-success; cyan `#00f1fd` = secondary/interactive/active/live; red `#ff3131` = critical/alert; amber `#ffb020` = warning/medium severity.
- Type floor: `font-label-caps` (11px) is the minimum for content labels; a single `label-xs` (10px) utility is permitted only for fixed dense chrome. No `text-[8px]`/`[9px]`, no inline `style={{ fontSize }}`.
- Verification is behavior-based: after each task run `cd ui && npx tsc --noEmit` (compare against the known pre-existing baseline — see Task 0) and `npm run build`, plus a live check on the dev server (`:5173`) against the running API (`:8200`). Vite HMR is live; most changes reflect without restart.
- Commit after every task. One focused commit per task; Phase 5 commits one page per task.

---

## Task 0: Establish the verification baseline

**Files:**
- Create: `ui/.tsc-baseline.txt` (git-ignored scratch; not committed)

**Interfaces:**
- Produces: a recorded count of pre-existing `tsc` errors so later tasks can prove they added zero new ones.

- [ ] **Step 1: Capture the current typecheck baseline**

Run:
```bash
cd ui && npx tsc --noEmit 2>&1 | tee /tmp/tsc-baseline.txt | grep -c "error TS"
```
Expected: a nonzero number (pre-existing errors — e.g. unused imports, CSS-module side-effect imports). Record it; call it `BASELINE`.

- [ ] **Step 2: Confirm the app builds and runs**

Run:
```bash
cd ui && npm run build 2>&1 | tail -5
```
Expected: build completes (Vite/esbuild tolerates the tsc-only errors). Confirm the dev server responds:
```bash
curl -s -o /dev/null -w "%{http_code}\n" http://127.0.0.1:5173
```
Expected: `200`. If not running, start it: `cd ui && npm run dev` (background).

- [ ] **Step 3: Confirm the API is serving real data**

Run:
```bash
curl -s -o /dev/null -w "%{http_code}\n" http://127.0.0.1:8200/health
```
Expected: `200`. This is the source of live data for per-page verification.

- [ ] **Step 4: No commit** (baseline is scratch only).

---

## Phase 1 — Unified design tokens (single source of truth)

### Task 1: Define canonical tokens as CSS variables

**Files:**
- Modify: `ui/src/styles.css` (the `:root` block, lines ~5–31)

**Interfaces:**
- Produces: the canonical token set as CSS variables — the single source both Tailwind and custom CSS read.

- [ ] **Step 1: Verify current variable usage**

Run:
```bash
cd ui && grep -rn "var(--primary-fixed)\|var(--secondary)\|var(--tertiary)\|var(--primary-container)" src/styles.css | head
```
Expected: custom effects (`hud-corners`, `scanline`, `glow-primary`) reference `var(--primary-fixed)` / `var(--tertiary)`. These must keep working after the remap.

- [ ] **Step 2: Replace the `:root` block with the canonical token set**

Replace the existing `:root { ... }` (surface + text + accent variables) in `ui/src/styles.css` with:

```css
:root {
  /* Surfaces (unchanged — the dark ramp is the identity) */
  --surface-container-lowest: #050506;
  --surface-container-low: #0a0a0b;
  --surface-container: #131314;
  --surface-container-high: #1a1a1d;
  --surface-container-highest: #2a2a2d;
  --surface-variant: #1a1a1a;
  --background: #050505;

  /* Text */
  --on-surface: #e5e2e3;
  --on-surface-variant: #9db3a6; /* contrast-tuned neutral (was #baccb0) */

  /* Accents — GREEN LEADS */
  --primary: #39ff14;            /* brand / operational / success */
  --primary-fixed: #39ff14;      /* alias kept for existing consumers */
  --primary-container: #107100;
  --on-primary-container: #efffe3;
  --on-primary: #00220a;

  --secondary: #00f1fd;          /* interactive / active / live */
  --secondary-container: #004f53;
  --on-secondary-container: #dcfdff;

  --critical: #ff3131;           /* critical / alert */
  --tertiary: #ff3131;           /* alias kept for existing consumers */
  --error: #ff3131;
  --error-container: #93000a;
  --on-error-container: #ffdad6;

  --warning: #ffb020;            /* NEW — warning / medium severity */
  --warning-container: #5c3d00;

  --outline: #333333;
  --outline-variant: #2a2a2d;
}
```

- [ ] **Step 3: Verify no visual break in effects**

Run: reload `:5173`. Expected: `hud-corners`, `scanline`, and hero glow still render green (they read `var(--primary-fixed)`, now `#39ff14`). No console errors.

- [ ] **Step 4: Commit**

```bash
cd ui && git add src/styles.css && git commit -m "style(ui): canonical design tokens as CSS variables (green leads, add warning)"
```

### Task 2: Point Tailwind color names at the token variables

**Files:**
- Modify: `ui/tailwind.config.js` (the `theme.extend.colors` block)

**Interfaces:**
- Consumes: the CSS variables from Task 1.
- Produces: Tailwind color utilities (`text-primary-fixed`, `bg-secondary`, …) that resolve to the same variables — eliminating the class-vs-variable conflict.

- [ ] **Step 1: Enumerate the color names the app actually uses**

Run:
```bash
cd ui && grep -rohE "(text|bg|border|from|via|to|fill|stroke)-(primary-fixed|secondary|tertiary|error|warning|primary-container|secondary-container|on-surface|on-surface-variant|surface-container[a-z-]*|outline-variant|outline|background)" src | sort -u
```
Expected: the concrete set of semantic color classes in use. Every name here must map to a token.

- [ ] **Step 2: Rewrite the `colors` block to reference variables**

Replace the `colors: { ... }` object in `ui/tailwind.config.js` with variable-backed values (retire the teal/mint literals). Keep every key currently referenced by the app; map each to a variable:

```js
colors: {
  background: "var(--background)",
  surface: "var(--surface-container-lowest)",
  "surface-variant": "var(--surface-variant)",
  "surface-container-lowest": "var(--surface-container-lowest)",
  "surface-container-low": "var(--surface-container-low)",
  "surface-container": "var(--surface-container)",
  "surface-container-high": "var(--surface-container-high)",
  "surface-container-highest": "var(--surface-container-highest)",
  "on-surface": "var(--on-surface)",
  "on-surface-variant": "var(--on-surface-variant)",
  primary: "var(--primary)",
  "primary-fixed": "var(--primary-fixed)",
  "primary-container": "var(--primary-container)",
  "on-primary": "var(--on-primary)",
  "on-primary-container": "var(--on-primary-container)",
  secondary: "var(--secondary)",
  "secondary-container": "var(--secondary-container)",
  "on-secondary-container": "var(--on-secondary-container)",
  tertiary: "var(--tertiary)",
  error: "var(--error)",
  "error-container": "var(--error-container)",
  "on-error-container": "var(--on-error-container)",
  warning: "var(--warning)",
  "warning-container": "var(--warning-container)",
  outline: "var(--outline)",
  "outline-variant": "var(--outline-variant)",
},
```

If Step 1 surfaced a used name not listed above, add it mapped to the closest token (do not leave it pointing at a retired literal).

- [ ] **Step 3: Verify the teal palette is gone**

Run:
```bash
cd ui && grep -rn "#24ffcd\|#00ffcc\|#ebffe6\|#00ff66" tailwind.config.js
```
Expected: no matches. Reload `:5173`; confirm active-nav and primary buttons now read from the unified tokens (cyan active nav, green primary) consistently across Overview, Findings, and Mission Control.

- [ ] **Step 4: Commit**

```bash
cd ui && git add tailwind.config.js && git commit -m "style(ui): Tailwind colors reference token variables (retire conflicting teal palette)"
```

### Task 3: Realign stale glow/effect colors to tokens

**Files:**
- Modify: `ui/src/styles.css` (lines ~169–192: `.glow-primary`, `.glow-danger`, `.glow-cyan`, `.glow-red`, `.glow-green`)

**Interfaces:**
- Produces: glow effects whose colors match the canonical accents (glows currently hardcode teal `0,255,204` and `#ff003c`).

- [ ] **Step 1: Confirm the mismatch**

Run:
```bash
cd ui && grep -n "0, 255, 204\|255, 0, 60\|0, 255, 102" src/styles.css
```
Expected: `.glow-cyan` (teal), `.glow-red` (#ff003c), `.glow-green` currently use off-token colors.

- [ ] **Step 2: Update the glow definitions**

Replace those glow rules with token-aligned RGBA (green `57,255,20`; cyan `0,241,253`; red `255,49,49`):

```css
.glow-primary { box-shadow: 0 0 15px rgba(57, 255, 20, 0.2); }
.glow-danger  { box-shadow: 0 0 15px rgba(255, 49, 49, 0.3); }
.glow-cyan    { box-shadow: 0 0 10px rgba(0, 241, 253, 0.3); }
.glow-red     { box-shadow: 0 0 10px rgba(255, 49, 49, 0.3); }
.glow-green   { box-shadow: 0 0 10px rgba(57, 255, 20, 0.3); }
```

- [ ] **Step 3: Verify**

Reload `:5173`; the `glow-cyan` on active nav and primary buttons now matches the cyan/green accents rather than teal. No layout change.

- [ ] **Step 4: Commit**

```bash
cd ui && git add src/styles.css && git commit -m "style(ui): realign glow effects to canonical accent colors"
```

---

## Phase 2 — Delete the duplicated utility layer

### Task 4: Remove hand-rolled utilities that duplicate Tailwind

**Files:**
- Modify: `ui/src/styles.css` (the utility block, roughly lines ~80–160: `.flex`, `.flex-col`, `.grid-cols-*`, `.p-*`, `.px-*`, `.border*`, `.bg-*`, `.text-*`, `.rounded-*`, `.truncate`, spacing/layout helpers)

**Interfaces:**
- Consumes: the unified Tailwind colors from Phase 1 (so deleting the hand-rolled color utilities is safe — Tailwind now generates equivalents from the same tokens).
- Produces: a `styles.css` containing only base styles, tokens, and genuine custom effects.

- [ ] **Step 1: Prove Tailwind provides each utility being deleted**

Run:
```bash
cd ui && grep -nE "^\.(flex|grid|grid-cols-[0-9]|p-[0-9]|px-[0-9]|py-[0-9]|border|bg-|text-|rounded|gap-|items-|justify-|h-|w-|z-|overflow|absolute|relative|inset|truncate|uppercase|italic|tracking)" src/styles.css | head -60
```
Expected: the list of hand-rolled utilities. All of these are standard Tailwind utilities (Tailwind 4 is a superset) EXCEPT the custom effect/component classes below, which must be KEPT.

- [ ] **Step 2: Delete ONLY the standard-utility duplicates**

Remove the hand-rolled block that re-implements standard Tailwind utilities. **KEEP** everything from `/* Custom Component Styles */` onward and all effect classes: `terminal-grid`, `.custom-scrollbar`, `.animate-pulse-neon`, `.cursor-blink`, `modal-overlay`, `briefing-room`, `tab-nav*`, `pane-container`, `glow-*`, `scanline`, `graph-*`, `node-*`, `link-line`, `legend-box`, `animate-spin`, `reveal-up`, `hud-corners`, `sweep-line`, `live-dot`, and all `@keyframes`. Keep the `:root`, `body`, base `h1–h4`, and scrollbar rules.

- [ ] **Step 3: Verify no regression across a sample of pages**

Run:
```bash
cd ui && npm run build 2>&1 | tail -3
```
Expected: clean build. Reload `:5173` and click through Overview, Mission Control, Findings, Knowledge Graphs, Learning. Expected: layout/spacing unchanged (Tailwind now supplies the utilities). Watch for any element that lost styling — if found, it depended on a non-standard hand-rolled class; restore just that class.

- [ ] **Step 4: Confirm file shrank and only effects remain**

Run:
```bash
cd ui && grep -cE "^\.(flex|grid-cols-[0-9]|p-[0-9]|bg-black)" src/styles.css
```
Expected: `0` (standard duplicates gone).

- [ ] **Step 5: Commit**

```bash
cd ui && git add src/styles.css && git commit -m "refactor(ui): delete hand-rolled utilities duplicating Tailwind (keep custom effects)"
```

---

## Phase 3 — Real type scale, kill micro-typography

### Task 5: Add the `label-xs` utility and audit micro-type

**Files:**
- Modify: `ui/tailwind.config.js` (`fontSize` block)

**Interfaces:**
- Produces: a single sanctioned 10px utility (`text-label-xs`) for fixed chrome; the 11px `label-caps` remains the content-label floor.

- [ ] **Step 1: Add the `label-xs` size**

In `ui/tailwind.config.js`, add to `fontSize`:

```js
"label-xs": ["10px", { lineHeight: "13px", letterSpacing: "0.12em", fontWeight: "700" }],
```

- [ ] **Step 2: Count the micro-type debt (for tracking)**

Run:
```bash
cd ui && grep -rc "text-\[8px\]\|text-\[9px\]\|text-\[10px\]" src/pages src/components | grep -v ":0" | awk -F: '{s+=$2} END {print "micro-type occurrences:", s}'
```
Record the count. Per-page fixes happen in Phase 5; shared chrome is fixed in Task 6.

- [ ] **Step 3: Commit**

```bash
cd ui && git add tailwind.config.js && git commit -m "style(ui): add label-xs (10px) size for fixed chrome"
```

### Task 6: Fix micro-type in always-present chrome

**Files:**
- Modify: `ui/src/components/layout/Sidebar.tsx`, `ui/src/components/layout/Header.tsx`, `ui/src/components/shared/NetworkHealth.tsx`

**Interfaces:**
- Produces: chrome that respects the type floor (11px labels, 10px only where dense and fixed).

- [ ] **Step 1: Replace sub-10px and raw pixel labels**

In each file, replace `text-[8px]` and `text-[9px]` with `font-label-caps` (11px) where space allows, or `text-label-xs` (10px) for genuinely dense fixed rows (e.g. NetworkHealth's LATENCY/THROUGHPUT captions). Do not shrink below 10px.

- [ ] **Step 2: Verify typecheck adds no new errors**

Run:
```bash
cd ui && npx tsc --noEmit 2>&1 | grep -c "error TS"
```
Expected: equals `BASELINE` from Task 0.

- [ ] **Step 3: Verify live**

Reload `:5173`. Expected: sidebar labels, header, and NetworkHealth are legible; no clipped text. Layout intact.

- [ ] **Step 4: Commit**

```bash
cd ui && git add src/components/layout/Sidebar.tsx src/components/layout/Header.tsx src/components/shared/NetworkHealth.tsx && git commit -m "style(ui): enforce type floor in sidebar/header/network chrome"
```

---

## Phase 4 — Shared primitive library

All primitives live in `ui/src/components/shared/` and are pure presentational components (data passed via props; no store coupling). Each is extracted from existing markup so behavior is preserved.

### Task 7: `Panel` (generalize `Card`)

**Files:**
- Create: `ui/src/components/shared/Panel.tsx`
- Modify: `ui/src/components/shared/Card.tsx` (delegate to `Panel` for back-compat)

**Interfaces:**
- Produces:
  - `Panel: React.FC<{ title?: string; action?: React.ReactNode; variant?: 'default'|'inset'; glow?: 'green'|'cyan'|'red'|'none'; className?: string; children: React.ReactNode }>`
  - `Card` keeps its existing signature `{ title: string; glow?: 'cyan'|'red'|'green'|'none'; className?; children }` and renders a `Panel`.

- [ ] **Step 1: Create `Panel.tsx`**

```tsx
import React from 'react';

export interface PanelProps {
  title?: string;
  action?: React.ReactNode;
  variant?: 'default' | 'inset';
  glow?: 'green' | 'cyan' | 'red' | 'none';
  className?: string;
  children: React.ReactNode;
}

export const Panel: React.FC<PanelProps> = ({
  title, action, variant = 'default', glow = 'none', className = '', children,
}) => {
  const base = variant === 'inset' ? 'bg-black/40' : 'bg-surface-container';
  const glowClass = glow === 'none' ? '' : `glow-${glow}`;
  return (
    <div className={`${base} border border-outline-variant p-6 flex flex-col relative overflow-hidden ${glowClass} ${className}`}>
      {title && (
        <div className="font-label-caps text-on-surface-variant mb-4 border-b border-outline-variant/30 pb-2 flex justify-between items-center uppercase opacity-80">
          <span>{title}</span>
          {action}
        </div>
      )}
      <div className="flex-1">{children}</div>
    </div>
  );
};
```

- [ ] **Step 2: Reimplement `Card` on top of `Panel`**

Replace `ui/src/components/shared/Card.tsx` body with:

```tsx
import React from 'react';
import { Panel } from './Panel';

interface CardProps {
  title: string;
  children: React.ReactNode;
  className?: string;
  glow?: 'cyan' | 'red' | 'green' | 'none';
}

export const Card: React.FC<CardProps> = ({ title, children, className = '', glow = 'none' }) => (
  <Panel title={title} glow={glow} className={className}>{children}</Panel>
);
```

- [ ] **Step 3: Verify**

Run: `cd ui && npx tsc --noEmit 2>&1 | grep -c "error TS"` (expect `BASELINE`). Reload `:5173`; every existing `Card` (Overview, etc.) renders identically.

- [ ] **Step 4: Commit**

```bash
cd ui && git add src/components/shared/Panel.tsx src/components/shared/Card.tsx && git commit -m "feat(ui): Panel primitive; Card delegates to it"
```

### Task 8: `StatusBadge` with severity/status color map

**Files:**
- Create: `ui/src/components/shared/StatusBadge.tsx`

**Interfaces:**
- Produces: `StatusBadge: React.FC<{ value?: string; kind?: 'status'|'severity' }>` — maps known status/severity strings to token colors, falls back to muted.

- [ ] **Step 1: Create `StatusBadge.tsx`**

```tsx
import React from 'react';

type Kind = 'status' | 'severity';

const STATUS: Record<string, string> = {
  verified:  'border-primary-fixed text-primary-fixed bg-primary-fixed/5',
  validated: 'border-secondary text-secondary bg-secondary/5',
  pending:   'border-outline text-on-surface-variant',
  rejected:  'border-outline text-on-surface-variant opacity-50 line-through',
};

const SEVERITY: Record<string, string> = {
  critical: 'border-error text-error bg-error/10',
  high:     'border-warning text-warning bg-warning/10',
  medium:   'border-warning text-warning bg-warning/5',
  low:      'border-secondary text-secondary bg-secondary/5',
  info:     'border-outline text-on-surface-variant',
};

export const StatusBadge: React.FC<{ value?: string; kind?: Kind }> = ({ value, kind = 'status' }) => {
  const key = (value || '').toLowerCase();
  const map = kind === 'severity' ? SEVERITY : STATUS;
  const cls = map[key] || 'border-outline text-on-surface-variant opacity-50';
  return (
    <span className={`px-2 py-0.5 border font-label-caps text-label-xs uppercase ${cls}`}>
      {(value || 'pending').toUpperCase()}
    </span>
  );
};
```

- [ ] **Step 2: Verify** — `cd ui && npx tsc --noEmit 2>&1 | grep -c "error TS"` equals `BASELINE`.

- [ ] **Step 3: Commit**

```bash
cd ui && git add src/components/shared/StatusBadge.tsx && git commit -m "feat(ui): StatusBadge primitive with severity/status color map"
```

### Task 9: `StatTile` (promote Overview's `KpiTile`)

**Files:**
- Create: `ui/src/components/shared/StatTile.tsx`

**Interfaces:**
- Produces: `StatTile: React.FC<{ label: string; value: React.ReactNode; caption?: string; accent?: 'primary'|'error'|'secondary'|'warning'|'muted'; icon?: React.ReactNode; meta?: string; delay?: number }>`.

- [ ] **Step 1: Create `StatTile.tsx`** (extracted from `Overview.KpiTile`, accent map extended with `warning`, pixel size replaced with `font-display-lg`):

```tsx
import React from 'react';

type Accent = 'primary' | 'error' | 'secondary' | 'warning' | 'muted';

const ACCENT: Record<Accent, { text: string; border: string }> = {
  primary:   { text: 'text-primary-fixed',      border: 'border-t-primary-fixed' },
  error:     { text: 'text-error',              border: 'border-t-error' },
  secondary: { text: 'text-secondary',          border: 'border-t-secondary' },
  warning:   { text: 'text-warning',            border: 'border-t-warning' },
  muted:     { text: 'text-on-surface-variant', border: 'border-t-outline-variant' },
};

export interface StatTileProps {
  label: string;
  value: React.ReactNode;
  caption?: string;
  accent?: Accent;
  icon?: React.ReactNode;
  meta?: string;
  delay?: number;
}

export const StatTile: React.FC<StatTileProps> = ({
  label, value, caption, accent = 'primary', icon, meta, delay = 0,
}) => {
  const a = ACCENT[accent];
  return (
    <div
      className={`reveal-up hud-corners group relative bg-surface-container border border-outline-variant border-t-2 ${a.border} p-5 overflow-hidden transition-all duration-300 hover:border-primary-fixed/40`}
      style={{ animationDelay: `${delay}ms` }}
    >
      <div className="absolute inset-0 terminal-grid opacity-[0.04] pointer-events-none" />
      <div className="relative flex items-start justify-between">
        <div className="font-label-caps text-on-surface-variant uppercase">{label}</div>
        {icon && <div className={`${a.text} opacity-40 group-hover:opacity-90 transition-opacity`}>{icon}</div>}
      </div>
      <div className="relative mt-4 flex items-end gap-3">
        <div className={`font-display-lg ${a.text} leading-none tabular-nums`}>{value}</div>
        {meta && <div className="mb-1.5 font-code-sm text-on-surface-variant">{meta}</div>}
      </div>
      {caption && <div className="relative mt-2 font-code-sm text-on-surface-variant/80 uppercase">{caption}</div>}
    </div>
  );
};
```

- [ ] **Step 2: Verify** — `cd ui && npx tsc --noEmit 2>&1 | grep -c "error TS"` equals `BASELINE`.

- [ ] **Step 3: Commit**

```bash
cd ui && git add src/components/shared/StatTile.tsx && git commit -m "feat(ui): StatTile primitive (promoted from Overview KpiTile)"
```

### Task 10: `DataTable` (sticky head + empty state)

**Files:**
- Create: `ui/src/components/shared/DataTable.tsx`

**Interfaces:**
- Produces:
  - `interface Column<T> { key: string; header: string; width?: string; render?: (row: T) => React.ReactNode }`
  - `DataTable: <T,>(props: { columns: Column<T>[]; rows: T[]; rowKey: (row: T) => string; empty?: React.ReactNode }) => JSX.Element`

- [ ] **Step 1: Create `DataTable.tsx`** (extracted from Overview's ledger table):

```tsx
import React from 'react';
import { EmptyState } from './EmptyState';

export interface Column<T> {
  key: string;
  header: string;
  width?: string;
  render?: (row: T) => React.ReactNode;
}

export function DataTable<T>({
  columns, rows, rowKey, empty,
}: {
  columns: Column<T>[];
  rows: T[];
  rowKey: (row: T) => string;
  empty?: React.ReactNode;
}) {
  return (
    <div className="overflow-y-auto custom-scrollbar -mx-2">
      <table className="w-full text-left font-code-sm">
        <thead className="sticky top-0 z-10">
          <tr className="text-on-surface-variant bg-surface-container-high">
            {columns.map((c) => (
              <th key={c.key} className={`px-3 py-2.5 font-label-caps text-label-xs uppercase ${c.width || ''}`}>
                {c.header}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {rows.map((row) => (
            <tr key={rowKey(row)} className="border-b border-outline-variant/30 hover:bg-surface-container-high/60 transition-colors group">
              {columns.map((c) => (
                <td key={c.key} className="px-3 py-2.5">
                  {c.render ? c.render(row) : String((row as any)[c.key] ?? '')}
                </td>
              ))}
            </tr>
          ))}
          {rows.length === 0 && (
            <tr>
              <td colSpan={columns.length} className="px-3 py-16 text-center">
                {empty || <EmptyState message="No data yet." />}
              </td>
            </tr>
          )}
        </tbody>
      </table>
    </div>
  );
}
```

- [ ] **Step 2: Verify** (after Task 11 provides `EmptyState`, this compiles). If executing in order, run Task 11 first, then: `cd ui && npx tsc --noEmit 2>&1 | grep -c "error TS"` equals `BASELINE`.

- [ ] **Step 3: Commit**

```bash
cd ui && git add src/components/shared/DataTable.tsx && git commit -m "feat(ui): DataTable primitive with sticky head + empty state"
```

### Task 11: `Skeleton`, `EmptyState`, `ErrorState`, `SectionHeader`

**Files:**
- Create: `ui/src/components/shared/Skeleton.tsx`
- Create: `ui/src/components/shared/EmptyState.tsx`
- Create: `ui/src/components/shared/ErrorState.tsx`
- Create: `ui/src/components/shared/SectionHeader.tsx`

**Interfaces:**
- Produces:
  - `Skeleton: React.FC<{ className?: string }>`
  - `EmptyState: React.FC<{ message: string; icon?: React.ReactNode; hint?: string }>`
  - `ErrorState: React.FC<{ message: string; onRetry?: () => void }>`
  - `SectionHeader: React.FC<{ title: string; subtitle?: string; action?: React.ReactNode }>`

> Note: create `EmptyState.tsx` before `DataTable.tsx` compiles (Task 10 imports it). Recommended order: 11 before 10.

- [ ] **Step 1: `Skeleton.tsx`**

```tsx
import React from 'react';
export const Skeleton: React.FC<{ className?: string }> = ({ className = '' }) => (
  <div className={`bg-surface-container-high/60 border border-outline-variant/40 animate-pulse ${className}`} />
);
```

- [ ] **Step 2: `EmptyState.tsx`**

```tsx
import React from 'react';
export const EmptyState: React.FC<{ message: string; icon?: React.ReactNode; hint?: string }> = ({ message, icon, hint }) => (
  <div className="flex flex-col items-center justify-center py-16 text-center">
    {icon && <div className="mb-3 text-on-surface-variant opacity-20 animate-pulse-neon">{icon}</div>}
    <div className="font-code-sm text-on-surface-variant/60 italic">{message}</div>
    {hint && <div className="mt-1 font-label-caps text-label-xs text-on-surface-variant/40 uppercase">{hint}</div>}
  </div>
);
```

- [ ] **Step 3: `ErrorState.tsx`**

```tsx
import React from 'react';
import { AlertTriangle } from 'lucide-react';
export const ErrorState: React.FC<{ message: string; onRetry?: () => void }> = ({ message, onRetry }) => (
  <div className="flex flex-col items-center justify-center py-16 text-center">
    <AlertTriangle size={26} className="mb-3 text-error opacity-70" />
    <div className="font-code-sm text-error/80">{message}</div>
    {onRetry && (
      <button onClick={onRetry} className="mt-4 px-4 py-1.5 border border-error text-error font-label-caps uppercase hover:bg-error/10 focus-visible:outline focus-visible:outline-2 focus-visible:outline-error transition-colors">
        Retry
      </button>
    )}
  </div>
);
```

- [ ] **Step 4: `SectionHeader.tsx`**

```tsx
import React from 'react';
export const SectionHeader: React.FC<{ title: string; subtitle?: string; action?: React.ReactNode }> = ({ title, subtitle, action }) => (
  <div className="flex items-end justify-between mb-4">
    <div>
      <h2 className="font-display-lg text-on-surface tracking-tight">{title}</h2>
      {subtitle && <div className="font-code-sm text-on-surface-variant/70 mt-0.5">{subtitle}</div>}
    </div>
    {action}
  </div>
);
```

- [ ] **Step 5: Verify** — `cd ui && npx tsc --noEmit 2>&1 | grep -c "error TS"` equals `BASELINE`.

- [ ] **Step 6: Commit**

```bash
cd ui && git add src/components/shared/Skeleton.tsx src/components/shared/EmptyState.tsx src/components/shared/ErrorState.tsx src/components/shared/SectionHeader.tsx && git commit -m "feat(ui): Skeleton/EmptyState/ErrorState/SectionHeader primitives"
```

### Task 12: Refactor Overview onto the primitives (reference implementation)

**Files:**
- Modify: `ui/src/pages/Overview.tsx`

**Interfaces:**
- Consumes: `StatTile`, `StatusBadge`, `DataTable`, `Panel`, `EmptyState`, `SectionHeader`.
- Produces: the canonical example every Phase 5 page follows.

- [ ] **Step 1: Replace local `KpiTile` with `StatTile`**

Delete the local `KpiTile`, `KpiProps`, and `ACCENT` definitions; import `StatTile` and pass the same props (the four KPI tiles keep identical labels/values/accents; `value` now renders at `font-display-lg` scale). Replace `StatusPill` usage with `StatusBadge`.

- [ ] **Step 2: Replace the ledger table with `DataTable`**

Define `columns` for Finding / Type / EV Score / Status (the EV Score and Status cells reuse the existing bar + `StatusBadge` render functions), pass `findings` as `rows`, and provide the existing "No findings yet" copy via the `empty` prop.

- [ ] **Step 3: Fix remaining micro-type** — replace any `text-[9px]`/`[10px]` and inline `style={{ fontSize }}` in this file with `font-label-caps` / `font-code-sm` / `font-display-lg`.

- [ ] **Step 4: Verify**

Run: `cd ui && npx tsc --noEmit 2>&1 | grep -c "error TS"` equals `BASELINE`. Reload `:5173` Overview against live data. Expected: KPIs, ledger, empty state, and health panel render equivalently, now from shared primitives; no `text-[8/9px]` remain (`grep -c "text-\[8px\]\|text-\[9px\]" src/pages/Overview.tsx` → `0`).

- [ ] **Step 5: Commit**

```bash
cd ui && git add src/pages/Overview.tsx && git commit -m "refactor(ui): Overview onto shared primitives (reference implementation)"
```

---

## Phase 5 — Page-by-page sweep

**Per-page task template (apply to each page below).** Each page is its own task and commit. The transformation is mechanical and verified live; do NOT rewrite behavior or data flow.

For page `PAGE`:

- [ ] **Step 1: Read the page and inventory its debt**

Run:
```bash
cd ui && grep -c "text-\[8px\]\|text-\[9px\]" src/pages/PAGE.tsx; grep -n "const .*: React.FC\|<table\|fontSize:" src/pages/PAGE.tsx
```
Identify: local stat/pill/table helpers → replace with `StatTile`/`StatusBadge`/`DataTable`; micro-type → type-scale classes; missing loading/empty/error branches.

- [ ] **Step 2: Apply primitives + states**

Replace local presentational helpers with the shared primitives (same props/data). Wrap data regions: while a fetch/store value is unpopulated show `Skeleton`; when empty show `EmptyState`; on a caught fetch error show `ErrorState`. Use `SectionHeader` for the page title. Replace `text-[8px]`/`[9px]` and inline `fontSize` per the type floor. Unify accent usage to semantic roles (success=green, active=cyan, critical=red, warning=amber).

- [ ] **Step 3: Verify typecheck**

Run: `cd ui && npx tsc --noEmit 2>&1 | grep -c "error TS"` — must equal `BASELINE`.

- [ ] **Step 4: Verify live**

Reload `:5173`, navigate to the page against the running API. Confirm: real data renders, loading→loaded transition shows skeleton then data, empty and error paths are reachable (e.g. temporarily point to a nonexistent engagement to see empty/error), no clipped/illegible text, accents correct. `grep -c "text-\[8px\]\|text-\[9px\]" src/pages/PAGE.tsx` → `0`.

- [ ] **Step 5: Commit**

```bash
cd ui && git add src/pages/PAGE.tsx && git commit -m "refactor(ui): PAGE onto shared primitives + loading/empty/error states"
```

**Pages (one task each), ordered by debt/impact:**

- [ ] **Task 13:** `RealityVerificationCenter` (20 micro-type occurrences)
- [ ] **Task 14:** `FindingsVerification` (19; also fix the `Link` `size` prop tsc error if trivially in-scope)
- [ ] **Task 15:** `VisualContext` (13)
- [ ] **Task 16:** `AuthAudit` (12)
- [ ] **Task 17:** `SkillIntelligence` (12)
- [ ] **Task 18:** `ResearchIntelligence` (11)
- [ ] **Task 19:** `LearningAnalytics` (11; recharts theming — align series colors to tokens)
- [ ] **Task 20:** `Administration` (11)
- [ ] **Task 21:** `UncertaintyEngine` (10)
- [ ] **Task 22:** `DifferentialAuth` (8)
- [ ] **Task 23:** `KnowledgeGraphs` (6; React Flow node styles — align to tokens, keep graph behavior)
- [ ] **Task 24:** `MissionReport` (5)
- [ ] **Task 25:** `MissionControl` (4)
- [ ] **Task 26:** `MissionTimeline` (4)

Also sweep shared modals/widgets with the same template:

- [ ] **Task 27:** `components/shared/EvidenceVaultModal` (8), `ApprovalQueue` (5), `NewMissionModal`, `ConnectionManager`, `NotificationProvider` — apply primitives/type-floor; verify each modal opens and functions live.

---

## Phase 6 — Accessibility pass

### Task 28: Contrast + reduced-motion

**Files:**
- Modify: `ui/src/styles.css`

**Interfaces:**
- Produces: AA-tuned neutral text and a `prefers-reduced-motion` guard.

- [ ] **Step 1: Confirm `--on-surface-variant` contrast**

The token was tuned to `#9db3a6` in Task 1. Verify body-variant text on `--surface-container` reads clearly; if any usage sits on near-black at small sizes, prefer `--on-surface` there.

- [ ] **Step 2: Add reduced-motion guard**

Append to `ui/src/styles.css`:

```css
@media (prefers-reduced-motion: reduce) {
  .reveal-up, .sweep-line, .live-dot, .animate-pulse-neon, .animate-spin, .scanline {
    animation: none !important;
  }
}
```

- [ ] **Step 3: Verify** — reload `:5173` with OS reduced-motion on; animations stop, content still visible. Typecheck unchanged.

- [ ] **Step 4: Commit**

```bash
cd ui && git add src/styles.css && git commit -m "a11y(ui): AA-tuned variant text + reduced-motion guard"
```

### Task 29: Focus rings + icon-button labels + keyboard nav

**Files:**
- Modify: `ui/src/styles.css` (global focus-visible), `ui/src/components/layout/Header.tsx`, `ui/src/components/layout/Sidebar.tsx`, and any icon-only buttons surfaced by the grep below.

**Interfaces:**
- Produces: visible keyboard focus everywhere and accessible names on icon-only controls.

- [ ] **Step 1: Add a global focus-visible ring**

Append to `ui/src/styles.css`:

```css
:where(a, button, select, input, [tabindex]):focus-visible {
  outline: 2px solid var(--secondary);
  outline-offset: 2px;
}
```

- [ ] **Step 2: Find icon-only controls lacking labels**

Run:
```bash
cd ui && grep -rn "<button" src/pages src/components | grep -iv "aria-label" | head -40
```
For each icon-only button (no text child), add `aria-label="<action>"`. The engagement `<select>` already has `aria-label` (Header).

- [ ] **Step 3: Verify keyboard nav**

Reload `:5173`; Tab through sidebar links, header buttons, and the engagement selector. Expected: visible cyan focus ring on each; Enter/Space activate; the selector is operable by keyboard.

- [ ] **Step 4: Verify typecheck** — equals `BASELINE`.

- [ ] **Step 5: Commit**

```bash
cd ui && git add -A && git commit -m "a11y(ui): global focus-visible ring + aria labels on icon buttons"
```

### Task 30: Final full-app regression pass

- [ ] **Step 1: Build + typecheck**

Run:
```bash
cd ui && npx tsc --noEmit 2>&1 | grep -c "error TS"   # equals BASELINE
cd ui && npm run build 2>&1 | tail -3                  # clean build
```

- [ ] **Step 2: Live click-through** — visit all 17 routes on `:5173` against the running API. Confirm real data, loading/empty/error states, consistent accents, legible type, working focus. Note any regression and fix before closing.

- [ ] **Step 3: No commit** unless Step 2 surfaced a fix.

---

## Self-Review

**Spec coverage:**
- Phase 1 (unified tokens) → Tasks 1–3. ✓
- Phase 2 (delete duplicated utilities) → Task 4. ✓
- Phase 3 (type scale) → Tasks 5–6 (+ per-page in Phase 5). ✓
- Phase 4 (primitives: StatTile, StatusBadge, DataTable, Panel, Skeleton, EmptyState, ErrorState, SectionHeader) → Tasks 7–11; Overview reference → Task 12. ✓
- Phase 5 (17-page sweep + shared widgets, loading/empty/error) → Tasks 13–27. ✓
- Phase 6 (a11y: contrast, reduced-motion, focus, aria, keyboard) → Tasks 28–30. ✓
- Constraints (frontend-only, no mock data, no deps, keep neon identity, green leads, amber warning, type floor, live verification) → Global Constraints + per-task verify steps. ✓

**Placeholder scan:** primitive tasks contain complete component source; token tasks contain exact values; page-sweep tasks are a concrete mechanical recipe with live verification (full per-page final JSX is intentionally not pre-written — the spec mandates live iteration per page, and inventing it would be unverifiable guesswork). No "TBD"/"add error handling"-style gaps.

**Type consistency:** `Panel`/`Card` props, `StatTile`/`StatusBadge`/`DataTable` signatures, and `Column<T>` are used consistently across tasks; `EmptyState` is created (Task 11) before `DataTable` consumes it (note added to run 11 before 10).
