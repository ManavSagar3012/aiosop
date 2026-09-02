#!/usr/bin/env python3
"""Fix dead loading skeleton conditions in store-backed pages."""

import os

UI_DIR = "src"

def read_file(rel_path):
    path = os.path.join(UI_DIR, rel_path)
    with open(path, 'r', encoding='utf-8', errors='replace') as f:
        return f.read()

def write_file(rel_path, content):
    path = os.path.join(UI_DIR, rel_path)
    with open(path, 'w', encoding='utf-8', newline='') as f:
        f.write(content)
    print(f"  Written: {rel_path}")


# ===================================================================
# Fix 1: Overview.tsx - use sessionId as loading proxy
# ===================================================================
print("\n=== 1. Overview.tsx - Fix loading condition ===")

ov = read_file("pages/Overview.tsx")

# The store initializes findings as [] (truthy), so !findings is always false.
# Instead, check if sessionId is null AND findings is empty (store initialized but no WS data)
# sessionId is initialized as null -- once set, data is streaming.
old_ov_check = """  // Show loading skeleton while store data initializes
  if (!findings) {"""

new_ov_check = """  // Show loading skeleton while waiting for first data
  if (!sessionId && findings.length === 0) {"""

ov = ov.replace(old_ov_check, new_ov_check)
write_file("pages/Overview.tsx", ov)


# ===================================================================
# Fix 2: MissionControl.tsx - use sessionId as loading proxy
# ===================================================================
print("\n=== 2. MissionControl.tsx - Fix loading condition ===")

mc = read_file("pages/MissionControl.tsx")

# Check what store agents come from. Let me just check sessionId + agents.length
old_mc_check = """  if (!agents) {"""

new_mc_check = """  // Loading skeleton while waiting for store data
  if (!sessionId && agents.length === 0) {"""

# But MissionControl already has `const { agents, budget } = useSwarmStore();`
# and `const { auditLog } = useIntelligenceStore();` but no sessionId!
# I need to add sessionId to the destructuring.

# Let me first fix the check, then add sessionId 
mc = mc.replace(old_mc_check, new_mc_check)

# Add sessionId to useIntelligenceStore destructuring
mc = mc.replace(
    "const { auditLog } = useIntelligenceStore();",
    "const { auditLog, sessionId } = useIntelligenceStore();"
)

write_file("pages/MissionControl.tsx", mc)


# ===================================================================
# Fix 3: FindingsVerification.tsx - use sessionId as loading proxy
# ===================================================================
print("\n=== 3. FindingsVerification.tsx - Fix loading condition ===")

fv = read_file("pages/FindingsVerification.tsx")

old_fv_check = """  // Loading skeleton while store initializes
  if (!findings) {"""

new_fv_check = """  // Loading skeleton while waiting for first data
  if (!sessionId && findings.length === 0) {"""

fv = fv.replace(old_fv_check, new_fv_check)
write_file("pages/FindingsVerification.tsx", fv)


# ===================================================================
# Fix 4: RealityVerificationCenter.tsx - use sessionId as loading proxy
# ===================================================================
print("\n=== 4. RealityVerificationCenter.tsx - Fix loading condition ===")

rvc = read_file("pages/RealityVerificationCenter.tsx")

old_rvc_check = """  // Loading skeleton while store initializes
  if (!verifications) {"""

new_rvc_check = """  // Loading skeleton while waiting for first data
  if (!sessionId && verifications.length === 0) {"""

rvc = rvc.replace(old_rvc_check, new_rvc_check)

# Need to add sessionId to the store destructuring
rvc = rvc.replace(
    "const { verifications } = useIntelligenceStore();",
    "const { verifications, sessionId } = useIntelligenceStore();"
)

write_file("pages/RealityVerificationCenter.tsx", rvc)


print("\n=== ALL FIXES COMPLETE ===")
