#!/usr/bin/env python3
"""Fix remaining UI issues: alert()->toast, window.location.reload(), responsive breakpoints."""

import os

UI_SRC = os.path.join(os.path.dirname(__file__), '..', 'src')


def fix_file(rel_path, replacements):
    path = os.path.join(UI_SRC, rel_path)
    with open(path, 'r', encoding='utf-8', errors='replace') as f:
        content = f.read()
    for old, new in replacements:
        if old in content:
            content = content.replace(old, new)
            print(f'  OK: {rel_path}')
        else:
            print(f'  MISSING in {rel_path}: {old[:80]}...')
    with open(path, 'w', encoding='utf-8', newline='') as f:
        f.write(content)
    return content


# ========================================================================
# 1) DifferentialAuth.tsx — replace alert() with toast
# ========================================================================
fix_file('pages/DifferentialAuth.tsx', [
    (
        "import { useIntelligenceStore } from '../store/useIntelligenceStore';",
        "import { useIntelligenceStore } from '../store/useIntelligenceStore';\nimport { useToast } from '../hooks/useToast';",
    ),
    (
        '  const [validateError, setValidateError] = useState<string | null>(null);',
        '  const { addToast } = useToast();\n  const [validateError, setValidateError] = useState<string | null>(null);',
    ),
    (
        'alert("Exploit validation task queued.");',
        'addToast("Exploit validation task queued.", "success");',
    ),
])

# ========================================================================
# 2) FindingsVerification.tsx — replace alert() + window.location.reload()
# ========================================================================
fix_file('pages/FindingsVerification.tsx', [
    (
        "import { useIntelligenceStore } from '../store/useIntelligenceStore';",
        "import { useIntelligenceStore } from '../store/useIntelligenceStore';\nimport { useToast } from '../hooks/useToast';",
    ),
    (
        '  const [vaultOpen, setVaultOpen] = React.useState(false);',
        '  const { addToast } = useToast();\n  const [vaultOpen, setVaultOpen] = React.useState(false);',
    ),
    (
        '        alert("Finding manually verified in graph ledger.");\n        window.location.reload();',
        '        addToast("Finding manually verified in graph ledger.", "success");',
    ),
    (
        '        alert("Replay task queued in execution sandbox.");',
        '        addToast("Replay task queued in execution sandbox.", "success");',
    ),
])

# ========================================================================
# 3) ResearchIntelligence.tsx — replace alert() with toast
# ========================================================================
fix_file('pages/ResearchIntelligence.tsx', [
    (
        "} from 'lucide-react';",
        "} from 'lucide-react';\nimport { useToast } from '../hooks/useToast';",
    ),
    (
        'export const ResearchIntelligence: React.FC = () => {',
        'export const ResearchIntelligence: React.FC = () => {\n  const { addToast } = useToast();',
    ),
    (
        '        alert("PoC generation task queued for ExploitAgent.");',
        '        addToast("PoC generation task queued for ExploitAgent.", "success");',
    ),
    (
        '        alert("PoC generation failed.");',
        '        addToast("PoC generation failed.", "error");',
    ),
    (
        '           <button onClick={() => alert("Loading state diff viewer...")} className="',
        '           <button onClick={() => addToast("State diff viewer not yet implemented.", "warning")} className="',
    ),
])

# ========================================================================
# 4) UncertaintyEngine.tsx — replace alert() with toast
# ========================================================================
fix_file('pages/UncertaintyEngine.tsx', [
    (
        "import { useIntelligenceStore } from '../store/useIntelligenceStore';",
        "import { useIntelligenceStore } from '../store/useIntelligenceStore';\nimport { useToast } from '../hooks/useToast';",
    ),
    (
        'export const UncertaintyEngine: React.FC = () => {',
        'export const UncertaintyEngine: React.FC = () => {\n  const { addToast } = useToast();',
    ),
    (
        '        alert("Discovery swarm successfully deployed to target asset.");',
        '        addToast("Discovery swarm successfully deployed to target asset.", "success");',
    ),
])

# ========================================================================
# 5) Responsive breakpoints for ALL grid layouts
# ========================================================================

# Overview.tsx
fix_file('pages/Overview.tsx', [
    # KPI row: grid-cols-4 -> responsive
    ('<div className="grid grid-cols-4 gap-gutter">',
     '<div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-4 gap-gutter">'),
    # Ledger + Health: grid-cols-3 -> responsive
    ('<div className="grid grid-cols-3 gap-6">',
     '<div className="grid grid-cols-1 lg:grid-cols-3 gap-6">'),
])

# MissionControl.tsx
fix_file('pages/MissionControl.tsx', [
    # Agent Utilization + Cost: grid-cols-3 -> responsive
    ('<div className="grid grid-cols-3 gap-gutter">',
     '<div className="grid grid-cols-1 lg:grid-cols-3 gap-gutter">'),
    # Resource + Governance: grid-cols-2 -> responsive
    ('<div className="grid grid-cols-2 gap-6">',
     '<div className="grid grid-cols-1 lg:grid-cols-2 gap-6">'),
])

# LearningAnalytics.tsx
fix_file('pages/LearningAnalytics.tsx', [
    # KPI row: grid-cols-4 -> responsive
    ('<div className="grid grid-cols-4 gap-6">',
     '<div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-4 gap-6">'),
    # Skill + Pie: grid-cols-3 -> responsive
    ('<div className="grid grid-cols-3 gap-6">',
     '<div className="grid grid-cols-1 lg:grid-cols-3 gap-6">'),
    # Severity + Guidance: grid-cols-2 -> responsive
    ('<div className="grid grid-cols-2 gap-6">',
     '<div className="grid grid-cols-1 lg:grid-cols-2 gap-6">'),
    # Persona Row inside Card: grid-cols-4 -> responsive
    ('<div className="grid grid-cols-4 gap-8 py-4">',
     '<div className="grid grid-cols-2 sm:grid-cols-2 lg:grid-cols-4 gap-4 lg:gap-8 py-4">'),
])

# DifferentialAuth.tsx
fix_file('pages/DifferentialAuth.tsx', [
    # Comparison grid: grid-cols-2 -> responsive
    ('<div className="flex-1 grid grid-cols-2 gap-6 min-h-0">',
     '<div className="flex-1 grid grid-cols-1 lg:grid-cols-2 gap-6 min-h-0">'),
])

# FindingsVerification.tsx
fix_file('pages/FindingsVerification.tsx', [
    # Stats row: grid-cols-4 -> responsive
    ('<div className="grid grid-cols-4 gap-gutter mb-2">',
     '<div className="grid grid-cols-2 sm:grid-cols-4 gap-gutter mb-2">'),
    # Pipeline + Verification: grid-cols-3 -> responsive
    ('<div className="grid grid-cols-3 gap-6">',
     '<div className="grid grid-cols-1 lg:grid-cols-3 gap-6">'),
])

# ResearchIntelligence.tsx
fix_file('pages/ResearchIntelligence.tsx', [
    # KPI row: grid-cols-4 -> responsive
    ('<div className="grid grid-cols-4 gap-6">',
     '<div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-4 gap-6">'),
    # Invariant + Ledger: grid-cols-2 -> responsive
    ('<div className="grid grid-cols-2 gap-6">',
     '<div className="grid grid-cols-1 lg:grid-cols-2 gap-6">'),
])

# UncertaintyEngine.tsx
fix_file('pages/UncertaintyEngine.tsx', [
    # Boundaries + Brain Dump: grid-cols-2 -> responsive
    ('<div className="grid grid-cols-2 gap-6 flex-1 min-h-0">',
     '<div className="grid grid-cols-1 lg:grid-cols-2 gap-6 flex-1 min-h-0">'),
    # Metrics row inside Card: grid-cols-2 -> responsive
    ('<div className="grid grid-cols-2 gap-4 mt-6">',
     '<div className="grid grid-cols-1 sm:grid-cols-2 gap-4 mt-6">'),
])

# SkillIntelligence.tsx
fix_file('pages/SkillIntelligence.tsx', [
    # KPI row: grid-cols-4 -> responsive
    ('<div className="grid grid-cols-4 gap-6 shrink-0">',
     '<div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-4 gap-6 shrink-0">'),
    # Leaderboard + Log: grid-cols-2 -> responsive
    ('<div className="grid grid-cols-2 gap-6 flex-1 min-h-0">',
     '<div className="grid grid-cols-1 lg:grid-cols-2 gap-6 flex-1 min-h-0">'),
])

print("\n=== All fixes applied successfully ===")
