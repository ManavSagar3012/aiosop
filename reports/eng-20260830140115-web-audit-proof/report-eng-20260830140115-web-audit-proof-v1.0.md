# CONFIDENTIAL / CLIENT-SENSITIVE
# Executive Summary
**Engagement ID:** eng-20260830140115-web-audit-proof
**Date Generated:** 2026-08-30
**Version:** v1.0

## Risk Narrative
**CONFIDENTIAL**

**Executive Risk Narrative — Engagement eng-20260830140115-web-audit-proof**

The security assessment of the in-scope environment (1 asset, 8 endpoints evaluated) yielded 28 total findings, of which 2 are rated Critical and 5 are rated High, alongside 1 Medium and 20 Informational items. The Critical findings are concentrated in the Redis deployment, where the installed version predates 8.2.2 and is susceptible to a Lua scripting integer overflow (remediated in 8.2.1) and a Lua parser use-after-free (remediated in 8.2.2) — memory-corruption defects reachable through the scripting interface with potential for remote code execution and full service compromise. These are compounded by three High-severity issues: a Redis Lua sandbox cross-user escape, an out-of-bounds read via Lua long-string delimiters, and SQL injection via the `username` parameter in the web application. The co-location of exploitable memory-corruption flaws and an injection flaw on a single asset materially elevates aggregate risk beyond what any individual finding would suggest, as these issues can be chained to deepen an attacker's foothold.

From a business-risk standpoint, the confirmed SQL injection places the backend data store at direct risk of unauthorized access, manipulation, or exfiltration, while the Redis vulnerabilities threaten the confidentiality, integrity, and availability of caching and session infrastructure — and in the worst case provide code execution on the host as a pivot point into the broader environment. The 20 informational findings, while not immediately exploitable, represent hardening opportunities that should be tracked to maturity. We recommend the following prioritized remediation path: (1) upgrade Redis to version 8.2.2 or later to close all four Lua-related findings; (2) remediate the SQL injection through parameterized queries and strict input validation; and (3) commission a focused retest to validate closure of all Critical and High items within the agreed remediation window. Until these actions are verified complete, the assessed asset should be treated as carrying an elevated risk of compromise.

**CONFIDENTIAL**

## Assessment Overview
- **Total Assets Discovered:** 1
- **Total Endpoints Mapped:** 8
- **Critical Vulnerabilities:** 2
- **High Vulnerabilities:** 5

## Key Findings Summary

- **high**: SQLI via parameter 'username' (web_audit differential) (sqli)

- **critical**: Redis < 8.2.1 lua script - Integer Overflow (rce)

- **critical**: Redis Lua Parser < 8.2.2 - Use After Free (rce)

- **high**: Redis Lua Sandbox < 8.2.2 - Cross-User Escape (rce)

- **high**: Redis  < 8.2.1 Lua Long-String Delimiter - Out-of-Bounds Read (rce)


# CONFIDENTIAL / CLIENT-SENSITIVE
# Technical Details
**Engagement ID:** eng-20260830140115-web-audit-proof

## Verified Vulnerabilities


### 1. SQLI via parameter 'username' (web_audit differential)
- **Severity**: high
- **Type**: sqli
- **Target**: unknown
- **Attack Technique**: T1190 - Exploit Public-Facing Application
- **OWASP**: A03:2021-Injection
- **CVSS**: 8.1 (High)

#### Description
web_audit differential confirmed SQLI at http://127.0.0.1:9199/api/v1/users?username=seed: parameter 'username' with probe "' OR '1'='1" produced a behavioral delta the control request lacked (error_signature=False, auth_bypass=False).

#### Remediation
Use parameterized queries / prepared statements; never concatenate input.


#### Proof of Concept / Evidence
```
[{"type": "web_audit_differential", "provenance": "web_audit", "url": "http://127.0.0.1:9199/api/v1/users?username=seed", "parameter": "username", "baseline_value": "audit_probe_baseline_77", "probe": "' OR '1'='1", "baseline_status": 200, "injected_status": 200, "error_signature": false, "auth_bypass": false}]
```
**Artifact SHA-256 Hash**: `a9dc1087fadc69feebbb01fdfc1cbcc2feb7272833f462b4e39d9c233ec31897`
**Chain of Custody ID**: `no-audit-event`

---

### 2. Redis < 8.2.1 lua script - Integer Overflow
- **Severity**: critical
- **Type**: rce
- **Target**: unknown
- **Attack Technique**: T1210 - Exploitation of Remote Services
- **OWASP**: A01:2021-Broken Access Control
- **CVSS**: 9.8 (Critical)

#### Description
Redis is an open source, in-memory database that persists on disk. Versions 8.2.1 and below allow an authenticated user to use a specially crafted Lua script to cause an integer overflow and potentially lead to remote code execution The problem exists in all versions of Redis with Lua scripting. This issue is fixed in version 8.2.2.


#### Remediation
Apply input validation and least-privilege controls.


#### Proof of Concept / Evidence
```
[{"type": "nuclei_finding", "template": "CVE-2025-46817", "matched_at": "127.0.0.1:6379", "url": "127.0.0.1:6379", "request": "const redis = require('nuclei/redis');\nconst info = redis.GetServerInfo(Host, Port);\nExport(info);", "response": "# Server\r\nredis_version:7.0.15\r\nredis_git_sha1:00000000\r\nredis_git_dirty:0\r\nredis_build_id:e53ff17674aa6190\r\nredis_mode:standalone\r\nos:Linux 6.6.87.2-microsoft-standard-WSL2 x86_64\r\narch_bits:64\r\nmonotonic_clock:POSIX clock_gettime\r\nmultiplexing_api:epoll\r\natomicvar_api:c11-builtin\r\ngcc_version:13.3.0\r\nprocess_id:183\r\nprocess_supervised:systemd\r\nrun_id:c4fd36f69fbeb77f9c93943a881955f0c1760c8b\r\ntcp_port:6379\r\nserver_time_usec:1788098756491895\r\nuptime_in_seconds:70524\r\nuptime_in_days:0\r\nhz:10\r\nconfigured_hz:10\r\nlru_clock:9713860\r\nexecutable:/usr/bin/redis-server\r\nconfig_file:/etc/redis/redis.conf\r\nio_threads_active:0\r\n\r\n# Clients\r\nconnected_clients:1\r\ncluster_connections:0\r\nmaxclients:10000\r\nclient_recent_max_input_buffer:0\r\nclient_recent_max_output_buffer:0\r\nblocked_clients:0\r\ntracking_clients:0\r\nclients_in_timeout_table:0\r\n\r\n# Memory\r\nused_memory:1266736\r\nused_memory_human:1.21M\r\nused_memory_rss:9175040\r\nused_memory_rss_human:8.75M\r\nused_memory_peak:1532184\r\nused_memory_peak_human:1.46M\r\nused_memory_peak_perc:82.68%\r\nused_memory_overhead:879536\r\nused_memory_startup:876080\r\nused_memory_dataset:387200\r\nused_memory_dataset_perc:99.12%\r\nallocator_allocated:1744144\r\nallocator_active:2129920\r\nallocator_resident:6922240\r\ntotal_system_memory:8153923584\r\ntotal_system_memory_human:7.59G\r\nused_memory_lua:35840\r\nused_memory_vm_eval:35840\r\nused_memory_lua_human:35.00K\r\nused_memory_scripts_eval:152\r\nnumber_of_cached_scripts:1\r\nnumber_of_functions:0\r\nnumber_of_libraries:0\r\nused_memory_vm_functions:32768\r\nused_memory_vm_total:68608\r\nused_memory_vm_total_human:67.00K\r\nused_memory_functions:200\r\nused_memory_scripts:352\r\nused_memory_scripts_human:352B\r\nmaxmemory:0\r\nmaxmemory_human:0B\r\nmaxmemory_policy:noeviction\r\nallocator_frag_ratio:1.22\r\nallocator_frag_bytes:385776\r\nallocator_rss_ratio:3.25\r\nallocator_rss_bytes:4792320\r\nrss_overhead_ratio:1.33\r\nrss_overhead_bytes:2252800\r\nmem_fragmentation_ratio:7.48\r\nmem_fragmentation_bytes:7948216\r\nmem_not_counted_for_evict:0\r\nmem_replication_backlog:0\r\nmem_total_replication_buffers:0\r\nmem_clients_slaves:0\r\nmem_clients_normal:0\r\nmem_cluster_links:0\r\nmem_aof_buffer:0\r\nmem_allocator:jemalloc-5.3.0\r\nactive_defrag_running:0\r\nlazyfree_pending_objects:0\r\nlazyfreed_objects:0\r\n\r\n# Persistence\r\nloading:0\r\nasync_loading:0\r\ncurrent_cow_peak:0\r\ncurrent_cow_size:0\r\ncurrent_cow_size_age:0\r\ncurrent_fork_perc:0.00\r\ncurrent_save_keys_processed:0\r\ncurrent_save_keys_total:0\r\nrdb_changes_since_last_save:0\r\nrdb_bgsave_in_progress:0\r\nrdb_last_save_time:1788028232\r\nrdb_last_bgsave_status:ok\r\nrdb_last_bgsave_time_sec:-1\r\nrdb_current_bgsave_time_sec:-1\r\nrdb_saves:0\r\nrdb_last_cow_size:0\r\nrdb_last_load_keys_expired:0\r\nrdb_last_load_keys_loaded:64\r\naof_enabled:0\r\naof_rewrite_in_progress:0\r\naof_rewrite_scheduled:0\r\naof_last_rewrite_time_sec:-1\r\naof_current_rewrite_time_sec:-1\r\naof_last_bgrewrite_status:ok\r\naof_rewrites:0\r\naof_rewrites_consecutive_failures:0\r\naof_last_write_status:ok\r\naof_last_cow_size:0\r\nmodule_fork_in_progress:0\r\nmodule_fork_last_cow_size:0\r\n\r\n# Stats\r\ntotal_connections_received:2164\r\ntotal_commands_processed:3203\r\ninstantaneous_ops_per_sec:0\r\ntotal_net_input_bytes:291633\r\ntotal_net_output_bytes:4049123\r\ntotal_net_repl_input_bytes:0\r\ntotal_net_repl_output_bytes:0\r\ninstantaneous_input_kbps:0.00\r\ninstantaneous_output_kbps:0.00\r\ninstantaneous_input_repl_kbps:0.00\r\ninstantaneous_output_repl_kbps:0.00\r\nrejected_connections:0\r\nsync_full:0\r\nsync_partial_ok:0\r\nsync_partial_err:0\r\nexpired_keys:0\r\nexpired_stale_perc:0.0

...[truncated 1985 chars — full evidence in the evidence vault; sha256 above covers the complete artifact]
```
**Artifact SHA-256 Hash**: `4137f5b836757d6a24d2bb519fff37d9d6b1b2e7920ac01ac99d7b7c152b9d62`
**Chain of Custody ID**: `no-audit-event`

---

### 3. Redis Lua Parser < 8.2.2 - Use After Free
- **Severity**: critical
- **Type**: rce
- **Target**: unknown
- **Attack Technique**: T1210 - Exploitation of Remote Services
- **OWASP**: A01:2021-Broken Access Control
- **CVSS**: 9.8 (Critical)

#### Description
Redis is an open source, in-memory database that persists on disk. Versions 8.2.1 and below allow an authenticated user to use a specially crafted Lua script to manipulate the garbage collector, trigger a use-after-free and potentially lead to remote code execution. The problem exists in all versions of Redis with Lua scripting. This issue is fixed in version 8.2.2. To workaround this issue without patching the redis-server executable is to prevent users from executing Lua scripts. This can be done using ACL to restrict EVAL and EVALSHA commands.


#### Remediation
Apply input validation and least-privilege controls.


#### Proof of Concept / Evidence
```
[{"type": "nuclei_finding", "template": "CVE-2025-49844", "matched_at": "127.0.0.1:6379", "url": "127.0.0.1:6379", "request": "const redis = require('nuclei/redis');\nconst info = redis.GetServerInfo(Host, Port);\nExport(info);", "response": "# Server\r\nredis_version:7.0.15\r\nredis_git_sha1:00000000\r\nredis_git_dirty:0\r\nredis_build_id:e53ff17674aa6190\r\nredis_mode:standalone\r\nos:Linux 6.6.87.2-microsoft-standard-WSL2 x86_64\r\narch_bits:64\r\nmonotonic_clock:POSIX clock_gettime\r\nmultiplexing_api:epoll\r\natomicvar_api:c11-builtin\r\ngcc_version:13.3.0\r\nprocess_id:183\r\nprocess_supervised:systemd\r\nrun_id:c4fd36f69fbeb77f9c93943a881955f0c1760c8b\r\ntcp_port:6379\r\nserver_time_usec:1788098756491895\r\nuptime_in_seconds:70524\r\nuptime_in_days:0\r\nhz:10\r\nconfigured_hz:10\r\nlru_clock:9713860\r\nexecutable:/usr/bin/redis-server\r\nconfig_file:/etc/redis/redis.conf\r\nio_threads_active:0\r\n\r\n# Clients\r\nconnected_clients:1\r\ncluster_connections:0\r\nmaxclients:10000\r\nclient_recent_max_input_buffer:0\r\nclient_recent_max_output_buffer:0\r\nblocked_clients:0\r\ntracking_clients:0\r\nclients_in_timeout_table:0\r\n\r\n# Memory\r\nused_memory:1266736\r\nused_memory_human:1.21M\r\nused_memory_rss:9175040\r\nused_memory_rss_human:8.75M\r\nused_memory_peak:1532184\r\nused_memory_peak_human:1.46M\r\nused_memory_peak_perc:82.68%\r\nused_memory_overhead:879536\r\nused_memory_startup:876080\r\nused_memory_dataset:387200\r\nused_memory_dataset_perc:99.12%\r\nallocator_allocated:1744144\r\nallocator_active:2129920\r\nallocator_resident:6922240\r\ntotal_system_memory:8153923584\r\ntotal_system_memory_human:7.59G\r\nused_memory_lua:35840\r\nused_memory_vm_eval:35840\r\nused_memory_lua_human:35.00K\r\nused_memory_scripts_eval:152\r\nnumber_of_cached_scripts:1\r\nnumber_of_functions:0\r\nnumber_of_libraries:0\r\nused_memory_vm_functions:32768\r\nused_memory_vm_total:68608\r\nused_memory_vm_total_human:67.00K\r\nused_memory_functions:200\r\nused_memory_scripts:352\r\nused_memory_scripts_human:352B\r\nmaxmemory:0\r\nmaxmemory_human:0B\r\nmaxmemory_policy:noeviction\r\nallocator_frag_ratio:1.22\r\nallocator_frag_bytes:385776\r\nallocator_rss_ratio:3.25\r\nallocator_rss_bytes:4792320\r\nrss_overhead_ratio:1.33\r\nrss_overhead_bytes:2252800\r\nmem_fragmentation_ratio:7.48\r\nmem_fragmentation_bytes:7948216\r\nmem_not_counted_for_evict:0\r\nmem_replication_backlog:0\r\nmem_total_replication_buffers:0\r\nmem_clients_slaves:0\r\nmem_clients_normal:0\r\nmem_cluster_links:0\r\nmem_aof_buffer:0\r\nmem_allocator:jemalloc-5.3.0\r\nactive_defrag_running:0\r\nlazyfree_pending_objects:0\r\nlazyfreed_objects:0\r\n\r\n# Persistence\r\nloading:0\r\nasync_loading:0\r\ncurrent_cow_peak:0\r\ncurrent_cow_size:0\r\ncurrent_cow_size_age:0\r\ncurrent_fork_perc:0.00\r\ncurrent_save_keys_processed:0\r\ncurrent_save_keys_total:0\r\nrdb_changes_since_last_save:0\r\nrdb_bgsave_in_progress:0\r\nrdb_last_save_time:1788028232\r\nrdb_last_bgsave_status:ok\r\nrdb_last_bgsave_time_sec:-1\r\nrdb_current_bgsave_time_sec:-1\r\nrdb_saves:0\r\nrdb_last_cow_size:0\r\nrdb_last_load_keys_expired:0\r\nrdb_last_load_keys_loaded:64\r\naof_enabled:0\r\naof_rewrite_in_progress:0\r\naof_rewrite_scheduled:0\r\naof_last_rewrite_time_sec:-1\r\naof_current_rewrite_time_sec:-1\r\naof_last_bgrewrite_status:ok\r\naof_rewrites:0\r\naof_rewrites_consecutive_failures:0\r\naof_last_write_status:ok\r\naof_last_cow_size:0\r\nmodule_fork_in_progress:0\r\nmodule_fork_last_cow_size:0\r\n\r\n# Stats\r\ntotal_connections_received:2164\r\ntotal_commands_processed:3203\r\ninstantaneous_ops_per_sec:0\r\ntotal_net_input_bytes:291633\r\ntotal_net_output_bytes:4049123\r\ntotal_net_repl_input_bytes:0\r\ntotal_net_repl_output_bytes:0\r\ninstantaneous_input_kbps:0.00\r\ninstantaneous_output_kbps:0.00\r\ninstantaneous_input_repl_kbps:0.00\r\ninstantaneous_output_repl_kbps:0.00\r\nrejected_connections:0\r\nsync_full:0\r\nsync_partial_ok:0\r\nsync_partial_err:0\r\nexpired_keys:0\r\nexpired_stale_perc:0.0

...[truncated 1985 chars — full evidence in the evidence vault; sha256 above covers the complete artifact]
```
**Artifact SHA-256 Hash**: `8c8aba4f61d39afa39191b511c8211d23d7f2471a93a5b2ef8e963e74801a342`
**Chain of Custody ID**: `no-audit-event`

---

### 4. Redis Lua Sandbox < 8.2.2 - Cross-User Escape
- **Severity**: high
- **Type**: rce
- **Target**: unknown
- **Attack Technique**: T1210 - Exploitation of Remote Services
- **OWASP**: A01:2021-Broken Access Control
- **CVSS**: 8.1 (High)

#### Description
Redis is an open source, in-memory database that persists on disk. Versions 8.2.1 and below allow an authenticated user to use a specially crafted Lua script to manipulate different LUA objects and potentially run their own code in the context of another user. The problem exists in all versions of Redis with LUA scripting. This issue is fixed in version 8.2.2. A workaround to mitigate the problem without patching the redis-server executable is to prevent users from executing LUA scripts. This can be done using ACL to block a script by restricting both the EVAL and FUNCTION command families.


#### Remediation
Apply input validation and least-privilege controls.


#### Proof of Concept / Evidence
```
[{"type": "nuclei_finding", "template": "CVE-2025-46818", "matched_at": "127.0.0.1:6379", "url": "127.0.0.1:6379", "request": "const redis = require('nuclei/redis');\nconst info = redis.GetServerInfo(Host, Port);\nExport(info);", "response": "# Server\r\nredis_version:7.0.15\r\nredis_git_sha1:00000000\r\nredis_git_dirty:0\r\nredis_build_id:e53ff17674aa6190\r\nredis_mode:standalone\r\nos:Linux 6.6.87.2-microsoft-standard-WSL2 x86_64\r\narch_bits:64\r\nmonotonic_clock:POSIX clock_gettime\r\nmultiplexing_api:epoll\r\natomicvar_api:c11-builtin\r\ngcc_version:13.3.0\r\nprocess_id:183\r\nprocess_supervised:systemd\r\nrun_id:c4fd36f69fbeb77f9c93943a881955f0c1760c8b\r\ntcp_port:6379\r\nserver_time_usec:1788098756491895\r\nuptime_in_seconds:70524\r\nuptime_in_days:0\r\nhz:10\r\nconfigured_hz:10\r\nlru_clock:9713860\r\nexecutable:/usr/bin/redis-server\r\nconfig_file:/etc/redis/redis.conf\r\nio_threads_active:0\r\n\r\n# Clients\r\nconnected_clients:1\r\ncluster_connections:0\r\nmaxclients:10000\r\nclient_recent_max_input_buffer:0\r\nclient_recent_max_output_buffer:0\r\nblocked_clients:0\r\ntracking_clients:0\r\nclients_in_timeout_table:0\r\n\r\n# Memory\r\nused_memory:1266736\r\nused_memory_human:1.21M\r\nused_memory_rss:9175040\r\nused_memory_rss_human:8.75M\r\nused_memory_peak:1532184\r\nused_memory_peak_human:1.46M\r\nused_memory_peak_perc:82.68%\r\nused_memory_overhead:879536\r\nused_memory_startup:876080\r\nused_memory_dataset:387200\r\nused_memory_dataset_perc:99.12%\r\nallocator_allocated:1744144\r\nallocator_active:2129920\r\nallocator_resident:6922240\r\ntotal_system_memory:8153923584\r\ntotal_system_memory_human:7.59G\r\nused_memory_lua:35840\r\nused_memory_vm_eval:35840\r\nused_memory_lua_human:35.00K\r\nused_memory_scripts_eval:152\r\nnumber_of_cached_scripts:1\r\nnumber_of_functions:0\r\nnumber_of_libraries:0\r\nused_memory_vm_functions:32768\r\nused_memory_vm_total:68608\r\nused_memory_vm_total_human:67.00K\r\nused_memory_functions:200\r\nused_memory_scripts:352\r\nused_memory_scripts_human:352B\r\nmaxmemory:0\r\nmaxmemory_human:0B\r\nmaxmemory_policy:noeviction\r\nallocator_frag_ratio:1.22\r\nallocator_frag_bytes:385776\r\nallocator_rss_ratio:3.25\r\nallocator_rss_bytes:4792320\r\nrss_overhead_ratio:1.33\r\nrss_overhead_bytes:2252800\r\nmem_fragmentation_ratio:7.48\r\nmem_fragmentation_bytes:7948216\r\nmem_not_counted_for_evict:0\r\nmem_replication_backlog:0\r\nmem_total_replication_buffers:0\r\nmem_clients_slaves:0\r\nmem_clients_normal:0\r\nmem_cluster_links:0\r\nmem_aof_buffer:0\r\nmem_allocator:jemalloc-5.3.0\r\nactive_defrag_running:0\r\nlazyfree_pending_objects:0\r\nlazyfreed_objects:0\r\n\r\n# Persistence\r\nloading:0\r\nasync_loading:0\r\ncurrent_cow_peak:0\r\ncurrent_cow_size:0\r\ncurrent_cow_size_age:0\r\ncurrent_fork_perc:0.00\r\ncurrent_save_keys_processed:0\r\ncurrent_save_keys_total:0\r\nrdb_changes_since_last_save:0\r\nrdb_bgsave_in_progress:0\r\nrdb_last_save_time:1788028232\r\nrdb_last_bgsave_status:ok\r\nrdb_last_bgsave_time_sec:-1\r\nrdb_current_bgsave_time_sec:-1\r\nrdb_saves:0\r\nrdb_last_cow_size:0\r\nrdb_last_load_keys_expired:0\r\nrdb_last_load_keys_loaded:64\r\naof_enabled:0\r\naof_rewrite_in_progress:0\r\naof_rewrite_scheduled:0\r\naof_last_rewrite_time_sec:-1\r\naof_current_rewrite_time_sec:-1\r\naof_last_bgrewrite_status:ok\r\naof_rewrites:0\r\naof_rewrites_consecutive_failures:0\r\naof_last_write_status:ok\r\naof_last_cow_size:0\r\nmodule_fork_in_progress:0\r\nmodule_fork_last_cow_size:0\r\n\r\n# Stats\r\ntotal_connections_received:2164\r\ntotal_commands_processed:3203\r\ninstantaneous_ops_per_sec:0\r\ntotal_net_input_bytes:291633\r\ntotal_net_output_bytes:4049123\r\ntotal_net_repl_input_bytes:0\r\ntotal_net_repl_output_bytes:0\r\ninstantaneous_input_kbps:0.00\r\ninstantaneous_output_kbps:0.00\r\ninstantaneous_input_repl_kbps:0.00\r\ninstantaneous_output_repl_kbps:0.00\r\nrejected_connections:0\r\nsync_full:0\r\nsync_partial_ok:0\r\nsync_partial_err:0\r\nexpired_keys:0\r\nexpired_stale_perc:0.0

...[truncated 1985 chars — full evidence in the evidence vault; sha256 above covers the complete artifact]
```
**Artifact SHA-256 Hash**: `29a8c9d4c97b8a6882630791c1603e49eee39adf31c54b2a529ff4e580f22986`
**Chain of Custody ID**: `no-audit-event`

---

### 5. Redis  < 8.2.1 Lua Long-String Delimiter - Out-of-Bounds Read
- **Severity**: high
- **Type**: rce
- **Target**: unknown
- **Attack Technique**: T1210 - Exploitation of Remote Services
- **OWASP**: A01:2021-Broken Access Control
- **CVSS**: 8.1 (High)

#### Description
Redis is an open source, in-memory database that persists on disk. Versions 8.2.1 and below allow an authenticated user to use a specially crafted LUA script to read out-of-bound data or crash the server and subsequent denial of service. The problem exists in all versions of Redis with Lua scripting. This issue is fixed in version 8.2.2. To workaround this issue without patching the redis-server executable is to prevent users from executing Lua scripts. This can be done using ACL to block a script by restricting both the EVAL and FUNCTION command families.


#### Remediation
Apply input validation and least-privilege controls.


#### Proof of Concept / Evidence
```
[{"type": "nuclei_finding", "template": "CVE-2025-46819", "matched_at": "127.0.0.1:6379", "url": "127.0.0.1:6379", "request": "const redis = require('nuclei/redis');\nconst info = redis.GetServerInfo(Host, Port);\nExport(info);", "response": "# Server\r\nredis_version:7.0.15\r\nredis_git_sha1:00000000\r\nredis_git_dirty:0\r\nredis_build_id:e53ff17674aa6190\r\nredis_mode:standalone\r\nos:Linux 6.6.87.2-microsoft-standard-WSL2 x86_64\r\narch_bits:64\r\nmonotonic_clock:POSIX clock_gettime\r\nmultiplexing_api:epoll\r\natomicvar_api:c11-builtin\r\ngcc_version:13.3.0\r\nprocess_id:183\r\nprocess_supervised:systemd\r\nrun_id:c4fd36f69fbeb77f9c93943a881955f0c1760c8b\r\ntcp_port:6379\r\nserver_time_usec:1788098756491895\r\nuptime_in_seconds:70524\r\nuptime_in_days:0\r\nhz:10\r\nconfigured_hz:10\r\nlru_clock:9713860\r\nexecutable:/usr/bin/redis-server\r\nconfig_file:/etc/redis/redis.conf\r\nio_threads_active:0\r\n\r\n# Clients\r\nconnected_clients:1\r\ncluster_connections:0\r\nmaxclients:10000\r\nclient_recent_max_input_buffer:0\r\nclient_recent_max_output_buffer:0\r\nblocked_clients:0\r\ntracking_clients:0\r\nclients_in_timeout_table:0\r\n\r\n# Memory\r\nused_memory:1266736\r\nused_memory_human:1.21M\r\nused_memory_rss:9175040\r\nused_memory_rss_human:8.75M\r\nused_memory_peak:1532184\r\nused_memory_peak_human:1.46M\r\nused_memory_peak_perc:82.68%\r\nused_memory_overhead:879536\r\nused_memory_startup:876080\r\nused_memory_dataset:387200\r\nused_memory_dataset_perc:99.12%\r\nallocator_allocated:1744144\r\nallocator_active:2129920\r\nallocator_resident:6922240\r\ntotal_system_memory:8153923584\r\ntotal_system_memory_human:7.59G\r\nused_memory_lua:35840\r\nused_memory_vm_eval:35840\r\nused_memory_lua_human:35.00K\r\nused_memory_scripts_eval:152\r\nnumber_of_cached_scripts:1\r\nnumber_of_functions:0\r\nnumber_of_libraries:0\r\nused_memory_vm_functions:32768\r\nused_memory_vm_total:68608\r\nused_memory_vm_total_human:67.00K\r\nused_memory_functions:200\r\nused_memory_scripts:352\r\nused_memory_scripts_human:352B\r\nmaxmemory:0\r\nmaxmemory_human:0B\r\nmaxmemory_policy:noeviction\r\nallocator_frag_ratio:1.22\r\nallocator_frag_bytes:385776\r\nallocator_rss_ratio:3.25\r\nallocator_rss_bytes:4792320\r\nrss_overhead_ratio:1.33\r\nrss_overhead_bytes:2252800\r\nmem_fragmentation_ratio:7.48\r\nmem_fragmentation_bytes:7948216\r\nmem_not_counted_for_evict:0\r\nmem_replication_backlog:0\r\nmem_total_replication_buffers:0\r\nmem_clients_slaves:0\r\nmem_clients_normal:0\r\nmem_cluster_links:0\r\nmem_aof_buffer:0\r\nmem_allocator:jemalloc-5.3.0\r\nactive_defrag_running:0\r\nlazyfree_pending_objects:0\r\nlazyfreed_objects:0\r\n\r\n# Persistence\r\nloading:0\r\nasync_loading:0\r\ncurrent_cow_peak:0\r\ncurrent_cow_size:0\r\ncurrent_cow_size_age:0\r\ncurrent_fork_perc:0.00\r\ncurrent_save_keys_processed:0\r\ncurrent_save_keys_total:0\r\nrdb_changes_since_last_save:0\r\nrdb_bgsave_in_progress:0\r\nrdb_last_save_time:1788028232\r\nrdb_last_bgsave_status:ok\r\nrdb_last_bgsave_time_sec:-1\r\nrdb_current_bgsave_time_sec:-1\r\nrdb_saves:0\r\nrdb_last_cow_size:0\r\nrdb_last_load_keys_expired:0\r\nrdb_last_load_keys_loaded:64\r\naof_enabled:0\r\naof_rewrite_in_progress:0\r\naof_rewrite_scheduled:0\r\naof_last_rewrite_time_sec:-1\r\naof_current_rewrite_time_sec:-1\r\naof_last_bgrewrite_status:ok\r\naof_rewrites:0\r\naof_rewrites_consecutive_failures:0\r\naof_last_write_status:ok\r\naof_last_cow_size:0\r\nmodule_fork_in_progress:0\r\nmodule_fork_last_cow_size:0\r\n\r\n# Stats\r\ntotal_connections_received:2164\r\ntotal_commands_processed:3203\r\ninstantaneous_ops_per_sec:0\r\ntotal_net_input_bytes:291633\r\ntotal_net_output_bytes:4049123\r\ntotal_net_repl_input_bytes:0\r\ntotal_net_repl_output_bytes:0\r\ninstantaneous_input_kbps:0.00\r\ninstantaneous_output_kbps:0.00\r\ninstantaneous_input_repl_kbps:0.00\r\ninstantaneous_output_repl_kbps:0.00\r\nrejected_connections:0\r\nsync_full:0\r\nsync_partial_ok:0\r\nsync_partial_err:0\r\nexpired_keys:0\r\nexpired_stale_perc:0.0

...[truncated 1985 chars — full evidence in the evidence vault; sha256 above covers the complete artifact]
```
**Artifact SHA-256 Hash**: `a332ea2aad093585e95b409a1c62d31907029c8d2dfd3a3160a8f634a81b2b89`
**Chain of Custody ID**: `no-audit-event`

---

### 6. Redis - Default Logins
- **Severity**: high
- **Type**: unknown
- **Target**: unknown
- **Attack Technique**: T1190 - Exploit Public-Facing Application
- **OWASP**: A01:2021-Broken Access Control
- **CVSS**: 8.1 (High)

#### Description
Redis service was accessed with easily guessed credentials.


#### Remediation
Apply input validation and least-privilege controls.


#### Proof of Concept / Evidence
```
[{"type": "nuclei_finding", "template": "redis-default-logins", "matched_at": "127.0.0.1:6379", "url": "127.0.0.1:6379", "request": "var m = require(\"nuclei/redis\");\nm.GetServerInfoAuth(Host, Port, Password);", "response": "# Server\r\nredis_version:7.0.15\r\nredis_git_sha1:00000000\r\nredis_git_dirty:0\r\nredis_build_id:e53ff17674aa6190\r\nredis_mode:standalone\r\nos:Linux 6.6.87.2-microsoft-standard-WSL2 x86_64\r\narch_bits:64\r\nmonotonic_clock:POSIX clock_gettime\r\nmultiplexing_api:epoll\r\natomicvar_api:c11-builtin\r\ngcc_version:13.3.0\r\nprocess_id:183\r\nprocess_supervised:systemd\r\nrun_id:c4fd36f69fbeb77f9c93943a881955f0c1760c8b\r\ntcp_port:6379\r\nserver_time_usec:1788098756676584\r\nuptime_in_seconds:70524\r\nuptime_in_days:0\r\nhz:10\r\nconfigured_hz:10\r\nlru_clock:9713860\r\nexecutable:/usr/bin/redis-server\r\nconfig_file:/etc/redis/redis.conf\r\nio_threads_active:0\r\n\r\n# Clients\r\nconnected_clients:3\r\ncluster_connections:0\r\nmaxclients:10000\r\nclient_recent_max_input_buffer:0\r\nclient_recent_max_output_buffer:0\r\nblocked_clients:0\r\ntracking_clients:0\r\nclients_in_timeout_table:0\r\n\r\n# Memory\r\nused_memory:1322456\r\nused_memory_human:1.26M\r\nused_memory_rss:9175040\r\nused_memory_rss_human:8.75M\r\nused_memory_peak:1532184\r\nused_memory_peak_human:1.46M\r\nused_memory_peak_perc:86.31%\r\nused_memory_overhead:879536\r\nused_memory_startup:876080\r\nused_memory_dataset:442920\r\nused_memory_dataset_perc:99.23%\r\nallocator_allocated:1820160\r\nallocator_active:2220032\r\nallocator_resident:7012352\r\ntotal_system_memory:8153923584\r\ntotal_system_memory_human:7.59G\r\nused_memory_lua:35840\r\nused_memory_vm_eval:35840\r\nused_memory_lua_human:35.00K\r\nused_memory_scripts_eval:152\r\nnumber_of_cached_scripts:1\r\nnumber_of_functions:0\r\nnumber_of_libraries:0\r\nused_memory_vm_functions:32768\r\nused_memory_vm_total:68608\r\nused_memory_vm_total_human:67.00K\r\nused_memory_functions:200\r\nused_memory_scripts:352\r\nused_memory_scripts_human:352B\r\nmaxmemory:0\r\nmaxmemory_human:0B\r\nmaxmemory_policy:noeviction\r\nallocator_frag_ratio:1.22\r\nallocator_frag_bytes:399872\r\nallocator_rss_ratio:3.16\r\nallocator_rss_bytes:4792320\r\nrss_overhead_ratio:1.31\r\nrss_overhead_bytes:2162688\r\nmem_fragmentation_ratio:7.48\r\nmem_fragmentation_bytes:7948216\r\nmem_not_counted_for_evict:0\r\nmem_replication_backlog:0\r\nmem_total_replication_buffers:0\r\nmem_clients_slaves:0\r\nmem_clients_normal:0\r\nmem_cluster_links:0\r\nmem_aof_buffer:0\r\nmem_allocator:jemalloc-5.3.0\r\nactive_defrag_running:0\r\nlazyfree_pending_objects:0\r\nlazyfreed_objects:0\r\n\r\n# Persistence\r\nloading:0\r\nasync_loading:0\r\ncurrent_cow_peak:0\r\ncurrent_cow_size:0\r\ncurrent_cow_size_age:0\r\ncurrent_fork_perc:0.00\r\ncurrent_save_keys_processed:0\r\ncurrent_save_keys_total:0\r\nrdb_changes_since_last_save:0\r\nrdb_bgsave_in_progress:0\r\nrdb_last_save_time:1788028232\r\nrdb_last_bgsave_status:ok\r\nrdb_last_bgsave_time_sec:-1\r\nrdb_current_bgsave_time_sec:-1\r\nrdb_saves:0\r\nrdb_last_cow_size:0\r\nrdb_last_load_keys_expired:0\r\nrdb_last_load_keys_loaded:64\r\naof_enabled:0\r\naof_rewrite_in_progress:0\r\naof_rewrite_scheduled:0\r\naof_last_rewrite_time_sec:-1\r\naof_current_rewrite_time_sec:-1\r\naof_last_bgrewrite_status:ok\r\naof_rewrites:0\r\naof_rewrites_consecutive_failures:0\r\naof_last_write_status:ok\r\naof_last_cow_size:0\r\nmodule_fork_in_progress:0\r\nmodule_fork_last_cow_size:0\r\n\r\n# Stats\r\ntotal_connections_received:2172\r\ntotal_commands_processed:3220\r\ninstantaneous_ops_per_sec:9\r\ntotal_net_input_bytes:292867\r\ntotal_net_output_bytes:4055785\r\ntotal_net_repl_input_bytes:0\r\ntotal_net_repl_output_bytes:0\r\ninstantaneous_input_kbps:0.60\r\ninstantaneous_output_kbps:3.87\r\ninstantaneous_input_repl_kbps:0.00\r\ninstantaneous_output_repl_kbps:0.00\r\nrejected_connections:0\r\nsync_full:0\r\nsync_partial_ok:0\r\nsync_partial_err:0\r\nexpired_keys:0\r\nexpired_stale_perc:0.00\r\nexpired_tim

...[truncated 1963 chars — full evidence in the evidence vault; sha256 above covers the complete artifact]
```
**Artifact SHA-256 Hash**: `bd360c72be0ce279b8d1ea070666104d0bb04015322be45a43469dd4172fc5ff`
**Chain of Custody ID**: `no-audit-event`

---

### 7. Redis Server - Unauthenticated Access
- **Severity**: high
- **Type**: unknown
- **Target**: unknown
- **Attack Technique**: T1190 - Exploit Public-Facing Application
- **OWASP**: A01:2021-Broken Access Control
- **CVSS**: 8.1 (High)

#### Description
Redis server without any required authentication was discovered.

#### Remediation
Apply input validation and least-privilege controls.


#### Proof of Concept / Evidence
```
[{"type": "nuclei_finding", "template": "exposed-redis", "matched_at": "127.0.0.1:6379", "url": "127.0.0.1:6379", "request": "info\r\nquit\r\n", "response": "$5019\r\n# Server\r\nredis_version:7.0.15\r\nredis_git_sha1:00000000\r\nredis_git_dirty:0\r\nredis_build_id:e53ff17674aa6190\r\nredis_mode:standalone\r\nos:Linux 6.6.87.2-microsoft-standard-WSL2 x86_64\r\narch_bits:64\r\nmonotonic_clock:POSIX clock_gettime\r\nmultiplexing_api:epoll\r\natomicvar_api:c11-builtin\r\ngcc_version:13.3.0\r\nprocess_id:183\r\nprocess_supervised:systemd\r\nrun_id:c4fd36f69fbeb77f9c93943a881955f0c1760c8b\r\ntcp_port:6379\r\nserver_time_usec:1788098758377211\r\nuptime_in_seconds:70526\r\nuptime_in_days:0\r\nhz:10\r\nconfigured_hz:10\r\nlru_clock:9713862\r\nexecutable:/usr/bin/redis-server\r\nconfig_file:/etc/redis/redis.conf\r\nio_threads_active:0\r\n\r\n# Clients\r\nconnected_clients:2\r\ncluster_connections:0\r\nmaxclients:10000\r\nclient_recent_max_input_buffer:20524\r\nclient_recent_max_output_buffer:0\r\nblocked_clients:0\r\ntracking_clients:0\r\nclients_in_timeout_table:0\r\n\r\n# Memory\r\nused_memory:1289576\r\nused_memory_human:1.23M\r\nused_memory_rss:9175040\r\nused_memory_rss_human:8.75M\r\nused_memory_peak:1532184\r\nused_memory_peak_human:1.46M\r\nused_memory_peak_perc:84.17%\r\nused_memory_overhead:901836\r\nused_memory_startup:876080\r\nused_memory_dataset:387740\r\nused_memory_dataset_perc:93.77%\r\nallocator_allocated:1819584\r\nallocator_active:2220032\r\nallocator_resident:7012352\r\ntotal_system_memory:8153923584\r\ntotal_system_memory_human:7.59G\r\nused_memory_lua:35840\r\nused_memory_vm_eval:35840\r\nused_memory_lua_human:35.00K\r\nused_memory_scripts_eval:152\r\nnumber_of_cached_scripts:1\r\nnumber_of_functions:0\r\nnumber_of_libraries:0\r\nused_memory_vm_functions:32768\r\nused_memory_vm_total:68608\r\nused_memory_vm_total_human:67.00K\r\nused_memory_functions:200\r\nused_memory_scripts:352\r\nused_memory_scripts_human:352B\r\nmaxmemory:0\r\nmaxmemory_human:0B\r\nmaxmemory_policy:noeviction\r\nallocator_frag_ratio:1.22\r\nallocator_frag_bytes:400448\r\nallocator_rss_ratio:3.16\r\nallocator_rss_bytes:4792320\r\nrss_overhead_ratio:1.31\r\nrss_overhead_bytes:2162688\r\nmem_fragmentation_ratio:7.34\r\nmem_fragmentation_bytes:7925400\r\nmem_not_counted_for_evict:0\r\nmem_replication_backlog:0\r\nmem_total_replication_buffers:", "extracted_results": null, "false_positive_signal": {"out_of_scan_scope": true, "matched_endpoint": "127.0.0.1:6379", "scoped_endpoints": ["127.0.0.1:80"], "reason": "nuclei matched a service on a host port this scan was not pointed at (shared-host service misattribution \u2014 real service, wrong engagement)"}}]
```
**Artifact SHA-256 Hash**: `a456af4e285fcee64794c314ab604eae42c8a86fe00174f54f67b572ee2cbdcc`
**Chain of Custody ID**: `no-audit-event`

---

### 8. Prometheus Metrics - Detect
- **Severity**: medium
- **Type**: unknown
- **Target**: unknown
- **Attack Technique**: T1190 - Exploit Public-Facing Application
- **OWASP**: A01:2021-Broken Access Control
- **CVSS**: 5.4 (Medium)

#### Description
Prometheus metrics page was detected.

#### Remediation
Apply input validation and least-privilege controls.


#### Proof of Concept / Evidence
```
[{"type": "nuclei_finding", "template": "prometheus-metrics", "matched_at": "http://127.0.0.1/metrics", "url": "http://127.0.0.1/", "request": "GET /metrics HTTP/1.1\r\nHost: 127.0.0.1\r\nUser-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:130.0) Gecko/20100101 Firefox/130.0\r\nConnection: close\r\nAccept: */*\r\nAccept-Language: en\r\nAccept-Encoding: gzip\r\n\r\n", "response": "HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: 25576\r\nContent-Type: text/plain; version=0.0.4; charset=utf-8\r\nDate: Sun, 30 Aug 2026 14:06:16 GMT\r\n\r\n# HELP juiceshop_llm_input_tokens_total Number of total input tokens processed\n# TYPE juiceshop_llm_input_tokens_total counter\njuiceshop_llm_input_tokens_total{app=\"juiceshop\"} 0\n\n# HELP juiceshop_llm_input_tokens Number of input tokens processed\n# TYPE juiceshop_llm_input_tokens counter\n\n# HELP juiceshop_llm_output_tokens_total Number of total output tokens processed\n# TYPE juiceshop_llm_output_tokens_total counter\njuiceshop_llm_output_tokens_total{app=\"juiceshop\"} 0\n\n# HELP juiceshop_llm_output_tokens Number of output tokens processed\n# TYPE juiceshop_llm_output_tokens counter\n\n# HELP juiceshop_llm_tool_calls_total Number of tool calls made\n# TYPE juiceshop_llm_tool_calls_total counter\n\n# HELP file_uploads_count Total number of successful file uploads grouped by file type.\n# TYPE file_uploads_count counter\n\n# HELP file_upload_errors Total number of failed file uploads grouped by file type.\n# TYPE file_upload_errors counter\n\n# HELP http_requests_count Total HTTP request count grouped by status code.\n# TYPE http_requests_count counter\nhttp_requests_count{status_code=\"2XX\",app=\"juiceshop\"} 2840\nhttp_requests_count{status_code=\"5XX\",app=\"juiceshop\"} 95\nhttp_requests_count{status_code=\"4XX\",app=\"juiceshop\"} 1\nhttp_requests_count{status_code=\"3XX\",app=\"juiceshop\"} 2\n\n# HELP juiceshop_startup_duration_seconds Duration juiceshop required to perform a certain task during startup\n# TYPE juiceshop_startup_duration_seconds gauge\njuiceshop_startup_duration_seconds{task=\"validateConfig\",app=\"juiceshop\"} 0.019118685\njuiceshop_startup_duration_seconds{task=\"cleanupFtpFolder\",app=\"juiceshop\"} 0.16240674\njuiceshop_startup_duration_seconds{task=\"validatePreconditions\",app=\"juiceshop\"} 0.890166709\njuiceshop_startup_duration_seconds{task=\"datacreator\",app=\"juiceshop\"} 5.030113737\njuiceshop_startup_duration_seconds{task=\"customizeApplication\",app=\"juiceshop\"} 0.011209468\njuiceshop_startup_duration_seconds{task=\"customizeEasterEgg\",app=\"juiceshop\"} 0.007464651\njuiceshop_startup_duration_seconds{task=\"ready\",app=\"juiceshop\"} 5.113\n\n# HELP process_cpu_user_seconds_total Total user CPU time spent in seconds.\n# TYPE process_cpu_user_seconds_total counter\nprocess_cpu_user_seconds_total{app=\"juiceshop\"} 31.261653\n\n# HELP process_cpu_system_seconds_total Total system CPU time spent in seconds.\n# TYPE process_cpu_system_seconds_total counter\nprocess_cpu_system_seconds_total{app=\"juiceshop\"} 8.02393\n\n# HELP process_cpu_seconds_total Total user and system CPU time spent in seconds.\n# TYPE process_cpu_seconds_total counter\nprocess_cpu_seconds_total{app=\"juiceshop\"} 39.285582999999995\n\n# HELP process_start_time_seconds Start time of the process since unix epoch in seconds.\n# TYPE process_start_time_seconds gauge\nprocess_start_time_seconds{app=\"juiceshop\"} 1788098739\n\n# HELP process_resident_memory_bytes Resident memory size in bytes.\n# TYPE process_resident_memory_bytes gauge\nprocess_resident_memory_bytes{app=\"juiceshop\"} 1561497600\n\n# HELP process_virtual_memory_bytes Virtual memory size in bytes.\n# TYPE process_virtual_memory_bytes gauge\nprocess_virtual_memory_bytes{app=\"juiceshop\"} 11818094592\n\n# HELP process_heap_bytes Process heap size in bytes.\n# TYPE process_heap_bytes gauge\nprocess_heap_bytes{app=\"juiceshop\"} 2144890880\n\n# HELP process_open_fds Number of open file descriptors.

...[truncated 23715 chars — full evidence in the evidence vault; sha256 above covers the complete artifact]
```
**Artifact SHA-256 Hash**: `a9e5bd45b6160aa260a0168d2fd1507b02f9fa84c1f0d2f4860860d8ac3164cb`
**Chain of Custody ID**: `no-audit-event`

---

### 9. Public Swagger API - Detect
- **Severity**: info
- **Type**: unknown
- **Target**: unknown
- **Attack Technique**: T1190 - Exploit Public-Facing Application
- **OWASP**: A01:2021-Broken Access Control
- **CVSS**: 0.0 (Informational)

#### Description
Public Swagger API was detected.


#### Remediation
Apply input validation and least-privilege controls.


#### Proof of Concept / Evidence
```
[{"type": "nuclei_finding", "template": "swagger-api", "matched_at": "http://127.0.0.1//api-docs/swagger.yaml", "url": "http://127.0.0.1/", "request": "GET //api-docs/swagger.yaml HTTP/1.1\r\nHost: 127.0.0.1\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:79.0) Gecko/20100101 Firefox/79.0\r\nAccept: text/html, application/json\r\nAccept-Language: en\r\nAccept-Encoding: gzip\r\n\r\n", "response": "HTTP/1.1 200 OK\r\nConnection: close\r\nTransfer-Encoding: chunked\r\nAccess-Control-Allow-Origin: *\r\nContent-Type: text/html; charset=utf-8\r\nDate: Sun, 30 Aug 2026 14:03:57 GMT\r\nEtag: W/\"c22-H8FH9nKD8DeX/nvIRrte6ZjP2a4\"\r\nFeature-Policy: payment 'self'\r\nVary: Accept-Encoding\r\nX-Content-Type-Options: nosniff\r\nX-Frame-Options: SAMEORIGIN\r\nX-Recruiting: /#/jobs\r\n\r\n\n<!-- HTML for static distribution bundle build -->\n<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n  <meta charset=\"UTF-8\">\n  \n  <title>Swagger UI</title>\n  <link rel=\"stylesheet\" type=\"text/css\" href=\"./swagger-ui.css\" >\n  <link rel=\"icon\" type=\"image/png\" href=\"./favicon-32x32.png\" sizes=\"32x32\" /><link rel=\"icon\" type=\"image/png\" href=\"./favicon-16x16.png\" sizes=\"16x16\" />\n  <style>\n    html\n    {\n      box-sizing: border-box;\n      overflow: -moz-scrollbars-vertical;\n      overflow-y: scroll;\n    }\n    *,\n    *:before,\n    *:after\n    {\n      box-sizing: inherit;\n    }\n\n    body {\n      margin:0;\n      background: #fafafa;\n    }\n  </style>\n</head>\n\n<body>\n\n<svg xmlns=\"http://www.w3.org/2000/svg\" xmlns:xlink=\"http://www.w3.org/1999/xlink\" style=\"position:absolute;width:0;height:0\">\n  <defs>\n    <symbol viewBox=\"0 0 20 20\" id=\"unlocked\">\n      <path d=\"M15.8 8H14V5.6C14 2.703 12.665 1 10 1 7.334 1 6 2.703 6 5.6V6h2v-.801C8 3.754 8.797 3 10 3c1.203 0 2 .754 2 2.199V8H4c-.553 0-1 .646-1 1.199V17c0 .549.428 1.139.951 1.307l1.197.387C5.672 18.861 6.55 19 7.1 19h5.8c.549 0 1.428-.139 1.951-.307l1.196-.387c.524-.167.953-.757.953-1.306V9.199C17 8.646 16.352 8 15.8 8z\"></path>\n    </symbol>\n\n    <symbol viewBox=\"0 0 20 20\" id=\"locked\">\n      <path d=\"M15.8 8H14V5.6C14 2.703 12.665 1 10 1 7.334 1 6 2.703 6 5.6V8H4c-.553 0-1 .646-1 1.199V17c0 .549.428 1.139.951 1.307l1.197.387C5.672 18.861 6.55 19 7.1 19h5.8c.549 0 1.428-.139 1.951-.307l1.196-.387c.524-.167.953-.757.953-1.306V9.199C17 8.646 16.352 8 15.8 8zM12 8H8V5.199C8 3.754 8.797 3 10 3c1.203 0 2 .754 2 2.199V8z\"/>\n    </symbol>\n\n    <symbol viewBox=\"0 0 20 20\" id=\"close\">\n      <path d=\"M14.348 14.849c-.469.469-1.229.469-1.697 0L10 11.819l-2.651 3.029c-.469.469-1.229.469-1.697 0-.469-.469-.469-1.229 0-1.697l2.758-3.15-2.759-3.152c-.469-.469-.469-1.228 0-1.697.469-.469 1.228-.469 1.697 0L10 8.183l2.651-3.031c.469-.469 1.228-.469 1.697 0 .469.469.469 1.229 0 1.697l-2.758 3.152 2.758 3.15c.469.469.469 1.229 0 1.698z\"/>\n    </symbol>\n\n    <symbol viewBox=\"0 0 20 20\" id=\"large-arrow\">\n      <path d=\"M13.25 10L6.109 2.58c-.268-.27-.268-.707 0-.979.268-.27.701-.27.969 0l7.83 7.908c.268.271.268.709 0 .979l-7.83 7.908c-.268.271-.701.27-.969 0-.268-.269-.268-.707 0-.979L13.25 10z\"/>\n    </symbol>\n\n    <symbol viewBox=\"0 0 20 20\" id=\"large-arrow-down\">\n      <path d=\"M17.418 6.109c.272-.268.709-.268.979 0s.271.701 0 .969l-7.908 7.83c-.27.268-.707.268-.979 0l-7.908-7.83c-.27-.268-.27-.701 0-.969.271-.268.709-.268.979 0L10 13.25l7.418-7.141z\"/>\n    </symbol>\n\n\n    <symbol viewBox=\"0 0 24 24\" id=\"jump-to\">\n      <path d=\"M19 7v4H5.83l3.58-3.59L8 6l-6 6 6 6 1.41-1.41L5.83 13H21V7z\"/>\n    </symbol>\n\n    <symbol viewBox=\"0 0 24 24\" id=\"expand\">\n      <path d=\"M10 18h4v-2h-4v2zM3 6v2h18V6H3zm3 7h12v-2H6v2z\"/>\n    </symbol>\n\n  </defs>\n</svg>\n\n<div id=\"swagger-ui\"></div>\n\n<script src=\"./swagger-ui-bundle.js\"> </script>\n<script src=\"./swagger-ui-standalone-preset.js\"> </script>\n<script src=\"./swagger-ui-init.js\"> </script>\n\n\n\n<style>\n  .swagger-ui .topbar .download-url-

...[truncated 97 chars — full evidence in the evidence vault; sha256 above covers the complete artifact]
```
**Artifact SHA-256 Hash**: `39065dbeecb18046ddff3b732a31e5fae071f049dee9c7124a3b1109c1d38e38`
**Chain of Custody ID**: `no-audit-event`

---

### 10. robots.txt endpoint prober
- **Severity**: info
- **Type**: unknown
- **Target**: unknown
- **Attack Technique**: T1190 - Exploit Public-Facing Application
- **OWASP**: A01:2021-Broken Access Control
- **CVSS**: 0.0 (Informational)

#### Description


#### Remediation
Apply input validation and least-privilege controls.


#### Proof of Concept / Evidence
```
[{"type": "nuclei_finding", "template": "robots-txt-endpoint", "matched_at": "http://127.0.0.1/robots.txt", "url": "http://127.0.0.1/", "request": "GET /robots.txt HTTP/1.1\r\nHost: 127.0.0.1\r\nUser-Agent: Mozilla/5.0 (Debian; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36\r\nConnection: close\r\nAccept: */*\r\nAccept-Language: en\r\nAccept-Encoding: gzip\r\n\r\n", "response": "HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: 28\r\nAccess-Control-Allow-Origin: *\r\nContent-Type: text/plain; charset=utf-8\r\nDate: Sun, 30 Aug 2026 14:06:07 GMT\r\nEtag: W/\"1c-8HgF6mNyhsSFK0pascC9uB0wjX0\"\r\nFeature-Policy: payment 'self'\r\nVary: Accept-Encoding\r\nX-Content-Type-Options: nosniff\r\nX-Frame-Options: SAMEORIGIN\r\nX-Recruiting: /#/jobs\r\n\r\nUser-agent: *\nDisallow: /ftp", "extracted_results": ["/ftp"]}]
```
**Artifact SHA-256 Hash**: `4a242857fe3eb25b658db1d226ed5c9927e8c1e459e32750f472c3526f5b6646`
**Chain of Custody ID**: `no-audit-event`

---

### 11. robots.txt file
- **Severity**: info
- **Type**: unknown
- **Target**: unknown
- **Attack Technique**: T1190 - Exploit Public-Facing Application
- **OWASP**: A01:2021-Broken Access Control
- **CVSS**: 0.0 (Informational)

#### Description


#### Remediation
Apply input validation and least-privilege controls.


#### Proof of Concept / Evidence
```
[{"type": "nuclei_finding", "template": "robots-txt", "matched_at": "http://127.0.0.1/robots.txt", "url": "http://127.0.0.1/", "request": "GET /robots.txt HTTP/1.1\r\nHost: 127.0.0.1\r\nUser-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_12_6) AppleWebKit/603.3.8 (KHTML, like Gecko) Version/10.1.2 Safari/603.3.8\r\nConnection: close\r\nAccept: */*\r\nAccept-Language: en\r\nAccept-Encoding: gzip\r\n\r\n", "response": "HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: 28\r\nAccess-Control-Allow-Origin: *\r\nContent-Type: text/plain; charset=utf-8\r\nDate: Sun, 30 Aug 2026 14:06:11 GMT\r\nEtag: W/\"1c-8HgF6mNyhsSFK0pascC9uB0wjX0\"\r\nFeature-Policy: payment 'self'\r\nVary: Accept-Encoding\r\nX-Content-Type-Options: nosniff\r\nX-Frame-Options: SAMEORIGIN\r\nX-Recruiting: /#/jobs\r\n\r\nUser-agent: *\nDisallow: /ftp", "extracted_results": null}]
```
**Artifact SHA-256 Hash**: `100e767613e723f18a7bb6e310a4c07e73bb14a4d47f3496e370d4a405424b9f`
**Chain of Custody ID**: `no-audit-event`

---

### 12. security.txt File
- **Severity**: info
- **Type**: unknown
- **Target**: unknown
- **Attack Technique**: T1190 - Exploit Public-Facing Application
- **OWASP**: A01:2021-Broken Access Control
- **CVSS**: 0.0 (Informational)

#### Description
File similar to robots.txt but intended to be read by humans wishing to contact a website’s owner about security issues. Often defines a security policy and contact details.


#### Remediation
Apply input validation and least-privilege controls.


#### Proof of Concept / Evidence
```
[{"type": "nuclei_finding", "template": "security-txt", "matched_at": "http://127.0.0.1/.well-known/security.txt", "url": "http://127.0.0.1/", "request": "GET /.well-known/security.txt HTTP/1.1\r\nHost: 127.0.0.1\r\nUser-Agent: Mozilla/5.0 (Macintosh, Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.6.1 Safari/605.1.15\r\nConnection: close\r\nAccept: */*\r\nAccept-Language: en\r\nAccept-Encoding: gzip\r\n\r\n", "response": "HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: 475\r\nAccess-Control-Allow-Origin: *\r\nContent-Type: text/plain; charset=utf-8\r\nDate: Sun, 30 Aug 2026 14:06:20 GMT\r\nEtag: W/\"1db-nuhRnPmCKh5goEe8p3EKQryt8j8\"\r\nFeature-Policy: payment 'self'\r\nVary: Accept-Encoding\r\nX-Content-Type-Options: nosniff\r\nX-Frame-Options: SAMEORIGIN\r\nX-Recruiting: /#/jobs\r\n\r\nContact: mailto:donotreply@owasp-juice.shop\nEncryption: https://keybase.io/bkimminich/pgp_keys.asc?fingerprint=19c01cb7157e4645e9e2c863062a85a8cbfbdcda\nAcknowledgements: /#/score-board\nPreferred-languages: en, ar, az, bg, bn, ca, cs, da, de, ga, el, es, et, fi, fr, ka, he, hi, hu, id, it, ja, ko, lv, my, nl, no, pl, pt, ro, ru, si, sv, th, tr, uk, zh\nHiring: /#/jobs\nCsaf: http://localhost:3000/.well-known/csaf/provider-metadata.json\nExpires: Mon, 30 Aug 2027 14:05:42 GMT", "extracted_results": [" mailto:donotreply@owasp-juice.shop"]}]
```
**Artifact SHA-256 Hash**: `f65d26fe5a25da5a6ffb1966e3490ae057269375cb6515596afd656cca4db7db`
**Chain of Custody ID**: `no-audit-event`

---

### 13. MySQL Info - Enumeration
- **Severity**: info
- **Type**: sqli
- **Target**: unknown
- **Attack Technique**: T1190 - Exploit Public-Facing Application
- **OWASP**: A03:2021-Injection
- **CVSS**: 0.0 (Informational)

#### Description
Connects to a MySQL server and prints information such as the protocol and version numbers


#### Remediation
Use parameterized queries / prepared statements; never concatenate input.


#### Proof of Concept / Evidence
```
[{"type": "nuclei_finding", "template": "mysql-info", "matched_at": "127.0.0.1:3306", "url": "127.0.0.1:3306", "request": "var m = require(\"nuclei/mysql\");\nvar c = m.MySQLClient();\nvar response = c.FingerprintMySQL(Host, Port);\nExport(response);", "response": "{\n  \"Host\": \"127.0.0.1\",\n  \"IP\": \"invalid IP\",\n  \"Port\": 0,\n  \"Protocol\": \"mysql\",\n  \"TLS\": false,\n  \"Transport\": \"tcp\",\n  \"Version\": \"8.0.36\",\n  \"Debug\": {\n    \"PacketType\": \"handshake\",\n    \"ErrorMessage\": \"\",\n    \"ErrorCode\": 0\n  },\n  \"Raw\": \"{\\\"packetType\\\":\\\"handshake\\\",\\\"errorMsg\\\":\\\"\\\",\\\"errorCode\\\":0}\"\n}", "extracted_results": ["Version: 8.0.36", "Transport: tcp"], "false_positive_signal": {"out_of_scan_scope": true, "matched_endpoint": "127.0.0.1:3306", "scoped_endpoints": ["127.0.0.1:80"], "reason": "nuclei matched a service on a host port this scan was not pointed at (shared-host service misattribution \u2014 real service, wrong engagement)"}}]
```
**Artifact SHA-256 Hash**: `2ef804cba9379266fd98bcb0dc31709988625cccd65f16ed8a5d0e6087267457`
**Chain of Custody ID**: `no-audit-event`

---

### 14. Redis Info - Detect
- **Severity**: info
- **Type**: unknown
- **Target**: unknown
- **Attack Technique**: T1190 - Exploit Public-Facing Application
- **OWASP**: A01:2021-Broken Access Control
- **CVSS**: 0.0 (Informational)

#### Description
Retrieves information (such as version number and architecture) from a Redis key-value store.


#### Remediation
Apply input validation and least-privilege controls.


#### Proof of Concept / Evidence
```
[{"type": "nuclei_finding", "template": "redis-info", "matched_at": "127.0.0.1:6379", "url": "127.0.0.1:6379", "request": "const redis = require('nuclei/redis');\nconst info = redis.GetServerInfo(Host, Port);\nExport(info);", "response": "# Server\r\nredis_version:7.0.15\r\nredis_git_sha1:00000000\r\nredis_git_dirty:0\r\nredis_build_id:e53ff17674aa6190\r\nredis_mode:standalone\r\nos:Linux 6.6.87.2-microsoft-standard-WSL2 x86_64\r\narch_bits:64\r\nmonotonic_clock:POSIX clock_gettime\r\nmultiplexing_api:epoll\r\natomicvar_api:c11-builtin\r\ngcc_version:13.3.0\r\nprocess_id:183\r\nprocess_supervised:systemd\r\nrun_id:c4fd36f69fbeb77f9c93943a881955f0c1760c8b\r\ntcp_port:6379\r\nserver_time_usec:1788098756491895\r\nuptime_in_seconds:70524\r\nuptime_in_days:0\r\nhz:10\r\nconfigured_hz:10\r\nlru_clock:9713860\r\nexecutable:/usr/bin/redis-server\r\nconfig_file:/etc/redis/redis.conf\r\nio_threads_active:0\r\n\r\n# Clients\r\nconnected_clients:1\r\ncluster_connections:0\r\nmaxclients:10000\r\nclient_recent_max_input_buffer:0\r\nclient_recent_max_output_buffer:0\r\nblocked_clients:0\r\ntracking_clients:0\r\nclients_in_timeout_table:0\r\n\r\n# Memory\r\nused_memory:1266736\r\nused_memory_human:1.21M\r\nused_memory_rss:9175040\r\nused_memory_rss_human:8.75M\r\nused_memory_peak:1532184\r\nused_memory_peak_human:1.46M\r\nused_memory_peak_perc:82.68%\r\nused_memory_overhead:879536\r\nused_memory_startup:876080\r\nused_memory_dataset:387200\r\nused_memory_dataset_perc:99.12%\r\nallocator_allocated:1744144\r\nallocator_active:2129920\r\nallocator_resident:6922240\r\ntotal_system_memory:8153923584\r\ntotal_system_memory_human:7.59G\r\nused_memory_lua:35840\r\nused_memory_vm_eval:35840\r\nused_memory_lua_human:35.00K\r\nused_memory_scripts_eval:152\r\nnumber_of_cached_scripts:1\r\nnumber_of_functions:0\r\nnumber_of_libraries:0\r\nused_memory_vm_functions:32768\r\nused_memory_vm_total:68608\r\nused_memory_vm_total_human:67.00K\r\nused_memory_functions:200\r\nused_memory_scripts:352\r\nused_memory_scripts_human:352B\r\nmaxmemory:0\r\nmaxmemory_human:0B\r\nmaxmemory_policy:noeviction\r\nallocator_frag_ratio:1.22\r\nallocator_frag_bytes:385776\r\nallocator_rss_ratio:3.25\r\nallocator_rss_bytes:4792320\r\nrss_overhead_ratio:1.33\r\nrss_overhead_bytes:2252800\r\nmem_fragmentation_ratio:7.48\r\nmem_fragmentation_bytes:7948216\r\nmem_not_counted_for_evict:0\r\nmem_replication_backlog:0\r\nmem_total_replication_buffers:0\r\nmem_clients_slaves:0\r\nmem_clients_normal:0\r\nmem_cluster_links:0\r\nmem_aof_buffer:0\r\nmem_allocator:jemalloc-5.3.0\r\nactive_defrag_running:0\r\nlazyfree_pending_objects:0\r\nlazyfreed_objects:0\r\n\r\n# Persistence\r\nloading:0\r\nasync_loading:0\r\ncurrent_cow_peak:0\r\ncurrent_cow_size:0\r\ncurrent_cow_size_age:0\r\ncurrent_fork_perc:0.00\r\ncurrent_save_keys_processed:0\r\ncurrent_save_keys_total:0\r\nrdb_changes_since_last_save:0\r\nrdb_bgsave_in_progress:0\r\nrdb_last_save_time:1788028232\r\nrdb_last_bgsave_status:ok\r\nrdb_last_bgsave_time_sec:-1\r\nrdb_current_bgsave_time_sec:-1\r\nrdb_saves:0\r\nrdb_last_cow_size:0\r\nrdb_last_load_keys_expired:0\r\nrdb_last_load_keys_loaded:64\r\naof_enabled:0\r\naof_rewrite_in_progress:0\r\naof_rewrite_scheduled:0\r\naof_last_rewrite_time_sec:-1\r\naof_current_rewrite_time_sec:-1\r\naof_last_bgrewrite_status:ok\r\naof_rewrites:0\r\naof_rewrites_consecutive_failures:0\r\naof_last_write_status:ok\r\naof_last_cow_size:0\r\nmodule_fork_in_progress:0\r\nmodule_fork_last_cow_size:0\r\n\r\n# Stats\r\ntotal_connections_received:2164\r\ntotal_commands_processed:3203\r\ninstantaneous_ops_per_sec:0\r\ntotal_net_input_bytes:291633\r\ntotal_net_output_bytes:4049123\r\ntotal_net_repl_input_bytes:0\r\ntotal_net_repl_output_bytes:0\r\ninstantaneous_input_kbps:0.00\r\ninstantaneous_output_kbps:0.00\r\ninstantaneous_input_repl_kbps:0.00\r\ninstantaneous_output_repl_kbps:0.00\r\nrejected_connections:0\r\nsync_full:0\r\nsync_partial_ok:0\r\nsync_partial_err:0\r\nexpired_keys:0\r\nexpired_stale_perc:0.00\r\

...[truncated 2153 chars — full evidence in the evidence vault; sha256 above covers the complete artifact]
```
**Artifact SHA-256 Hash**: `14b792ef28cfb4a503b1284ac286dc1890630a8ae87391a3547dcb7d9ce6514a`
**Chain of Custody ID**: `no-audit-event`

---

### 15. SMB Version - Detection
- **Severity**: info
- **Type**: unknown
- **Target**: unknown
- **Attack Technique**: T1190 - Exploit Public-Facing Application
- **OWASP**: A01:2021-Broken Access Control
- **CVSS**: 0.0 (Informational)

#### Description
SMB version detection involves identifying the specific Server Message Block protocol version used by a system or network. This process is crucial for ensuring compatibility and security, as different SMB versions may have distinct features and vulnerabilities.


#### Remediation
Apply input validation and least-privilege controls.


#### Proof of Concept / Evidence
```
[{"type": "nuclei_finding", "template": "smb-version-detect", "matched_at": "127.0.0.1:445", "url": "127.0.0.1:445", "request": "let m = require(\"nuclei/smb\");\nlet c = new m.SMBClient();\nlet response = c.ConnectSMBInfoMode(Host, Port);\nExport(response);", "response": "{\n  \"SupportV1\": false,\n  \"Version\": {\n    \"Major\": 2,\n    \"Minor\": 1,\n    \"Revision\": 0,\n    \"VerString\": \"SMB 2.1\"\n  },\n  \"NativeOs\": \"\",\n  \"NTLM\": \"\",\n  \"GroupName\": \"\",\n  \"Capabilities\": {\n    \"DFSSupport\": true,\n    \"Leasing\": true,\n    \"LargeMTU\": true,\n    \"MultiChan\": false,\n    \"Persist\": false,\n    \"DirLeasing\": false,\n    \"Encryption\": false\n  },\n  \"HasNTLM\": true,\n  \"NegotiationLog\": {\n    \"HeaderLog\": {\n      \"ProtocolID\": [\n        0,\n        0,\n        0,\n        0,\n        254,\n        83,\n        77,\n        66\n      ],\n      \"Status\": 0,\n      \"Command\": 0,\n      \"Credits\": 1,\n      \"Flags\": 1\n    },\n    \"ProtocolID\": [\n      0,\n      0,\n      0,\n      0,\n      254,\n      83,\n      77,\n      66\n    ],\n    \"Status\": 0,\n    \"Command\": 0,\n    \"Credits\": 1,\n    \"Flags\": 1,\n    \"SecurityMode\": 3,\n    \"DialectRevision\": 528,\n    \"ServerGuid\": [\n      0,\n      0,\n      0,\n      0,\n      0,\n      0,\n      0,\n      0,\n      0,\n      0,\n      0,\n      0,\n      0,\n      0,\n      0,\n      0,\n      244,\n      117,\n      7,\n      244,\n      85,\n      143,\n      174,\n      70,\n      151,\n      62,\n      59,\n      42,\n      30,\n      59,\n      134,\n      201\n    ],\n    \"Capabilities\": 7,\n    \"SystemTime\": 1788098756,\n    \"ServerStartTime\": 1240428288,\n    \"AuthenticationTypes\": [\n      \"1.3.6.1.4.1.311.2.2.30\",\n      \"1.3.6.1.4.1.311.2.2.10\"\n    ]\n  },\n  \"SessionSetupLog\": {\n    \"HeaderLog\": {\n      \"ProtocolID\": [\n        0,\n        0,\n        0,\n        0,\n        254,\n        83,\n        77,\n        66\n      ],\n      \"Status\": 3221225494,\n      \"Command\": 1,\n      \"Credits\": 1,\n      \"Flags\": 1\n    },\n    \"ProtocolID\": [\n      0,\n      0,\n      0,\n      0,\n      254,\n      83,\n      77,\n      66\n    ],\n    \"Status\": 3221225494,\n    \"Command\": 1,\n    \"Credits\": 1,\n    \"Flags\": 1,\n    \"SetupFlags\": 0,\n    \"TargetName\": \"DESKTOP-VJ5O45D\",\n    \"NegotiateFlags\": 2726953477\n  }\n}", "extracted_results": ["SMB 2.1"], "false_positive_signal": {"out_of_scan_scope": true, "matched_endpoint": "127.0.0.1:445", "scoped_endpoints": ["127.0.0.1:80"], "reason": "nuclei matched a service on a host port this scan was not pointed at (shared-host service misattribution \u2014 real service, wrong engagement)"}}]
```
**Artifact SHA-256 Hash**: `a20832b7eb7539bdd6693f9439f8c6fe30482df199ff83a090ceebe4447e6602`
**Chain of Custody ID**: `no-audit-event`

---

### 16. SMB2 Server Time - Detection
- **Severity**: info
- **Type**: unknown
- **Target**: unknown
- **Attack Technique**: T1190 - Exploit Public-Facing Application
- **OWASP**: A01:2021-Broken Access Control
- **CVSS**: 0.0 (Informational)

#### Description
Trying to retrieve the present date of the system along with the initiation date of an SMB2 server.


#### Remediation
Apply input validation and least-privilege controls.


#### Proof of Concept / Evidence
```
[{"type": "nuclei_finding", "template": "smb2-server-time", "matched_at": "127.0.0.1:445", "url": "127.0.0.1:445", "request": "var m = require(\"nuclei/smb\");\nvar c = m.SMBClient();\nvar response = c.ConnectSMBInfoMode(Host, Port);\nvar systemTime = new Date(response.NegotiationLog.SystemTime * 1000).toISOString();\nvar serverstartTime = new Date(response.NegotiationLog.ServerStartTime * 1000).toISOString();\nvar result = \"SystemTime: \" + systemTime + \" ServerStartTime: \" + serverstartTime;\nresult", "response": "SystemTime: 2026-08-30T14:05:56.000Z ServerStartTime: 2009-04-22T19:24:48.000Z", "extracted_results": ["SystemTime: 2026-08-30T14:05:56.000Z ServerStartTime: 2009-04-22T19:24:48.000Z"], "false_positive_signal": {"out_of_scan_scope": true, "matched_endpoint": "127.0.0.1:445", "scoped_endpoints": ["127.0.0.1:80"], "reason": "nuclei matched a service on a host port this scan was not pointed at (shared-host service misattribution \u2014 real service, wrong engagement)"}}]
```
**Artifact SHA-256 Hash**: `65ef58d54e12d747f85bac38e75c81becb3911e4e92516f3518eae33028708fd`
**Chain of Custody ID**: `no-audit-event`

---

### 17. SMB - Enum Domains
- **Severity**: info
- **Type**: unknown
- **Target**: unknown
- **Attack Technique**: T1190 - Exploit Public-Facing Application
- **OWASP**: A01:2021-Broken Access Control
- **CVSS**: 0.0 (Informational)

#### Description
SMB enumeration of domains is often part of the reconnaissance phase, where security professionals or attackers attempt to gather information about the target network to identify potential vulnerabilities.


#### Remediation
Apply input validation and least-privilege controls.


#### Proof of Concept / Evidence
```
[{"type": "nuclei_finding", "template": "smb-enum-domains", "matched_at": "127.0.0.1:445", "url": "127.0.0.1:445", "request": "var m = require(\"nuclei/smb\");\nvar c = new m.SMBClient();\nvar response = c.ListSMBv2Metadata(Host, Port);\nExport(response);", "response": "{\n  \"SigningEnabled\": true,\n  \"SigningRequired\": true,\n  \"OSVersion\": \"10.0.26100\",\n  \"NetBIOSComputerName\": \"DESKTOP-VJ5O45D\",\n  \"NetBIOSDomainName\": \"DESKTOP-VJ5O45D\",\n  \"DNSComputerName\": \"DESKTOP-VJ5O45D\",\n  \"DNSDomainName\": \"DESKTOP-VJ5O45D\",\n  \"ForestName\": \"\"\n}", "extracted_results": ["DomainName: DESKTOP-VJ5O45D"], "false_positive_signal": {"out_of_scan_scope": true, "matched_endpoint": "127.0.0.1:445", "scoped_endpoints": ["127.0.0.1:80"], "reason": "nuclei matched a service on a host port this scan was not pointed at (shared-host service misattribution \u2014 real service, wrong engagement)"}}]
```
**Artifact SHA-256 Hash**: `99031d97b2cf79fefe7bfb9d1a675b38fba8ccde07c7e7d004f5ad5a62343ac9`
**Chain of Custody ID**: `no-audit-event`

---

### 18. SMB - Enumeration
- **Severity**: info
- **Type**: unknown
- **Target**: unknown
- **Attack Technique**: T1190 - Exploit Public-Facing Application
- **OWASP**: A01:2021-Broken Access Control
- **CVSS**: 0.0 (Informational)

#### Description
SMS Information Extraction is a sophisticated and efficient system designed to retrieve critical information from a remote computer or device through short text messages. This technology enables users to remotely access essential details about a computer, such as its operating system (OS) version, computer name, and hostname,
all via SMS communication.


#### Remediation
Apply input validation and least-privilege controls.


#### Proof of Concept / Evidence
```
[{"type": "nuclei_finding", "template": "smb-enum", "matched_at": "127.0.0.1:445", "url": "127.0.0.1:445", "request": "var m = require(\"nuclei/smb\");\nvar c = m.SMBClient();\nvar response = c.ListSMBv2Metadata(Host, Port);\nExport(response);", "response": "{\n  \"SigningEnabled\": true,\n  \"SigningRequired\": true,\n  \"OSVersion\": \"10.0.26100\",\n  \"NetBIOSComputerName\": \"DESKTOP-VJ5O45D\",\n  \"NetBIOSDomainName\": \"DESKTOP-VJ5O45D\",\n  \"DNSComputerName\": \"DESKTOP-VJ5O45D\",\n  \"DNSDomainName\": \"DESKTOP-VJ5O45D\",\n  \"ForestName\": \"\"\n}", "extracted_results": ["NetBIOSDomainName: DESKTOP-VJ5O45D", "DNSComputerNamen: DESKTOP-VJ5O45D", "DNSComputerName: DESKTOP-VJ5O45D", "ForestName: ", "OSVersion: 10.0.26100", "NetBIOSComputerName: DESKTOP-VJ5O45D"], "false_positive_signal": {"out_of_scan_scope": true, "matched_endpoint": "127.0.0.1:445", "scoped_endpoints": ["127.0.0.1:80"], "reason": "nuclei matched a service on a host port this scan was not pointed at (shared-host service misattribution \u2014 real service, wrong engagement)"}}]
```
**Artifact SHA-256 Hash**: `d7ebeb02799eb09ab88791b3f6d19d455402d9a805657d93223123599a0f8e96`
**Chain of Custody ID**: `no-audit-event`

---

### 19. SMB Operating System - Detect
- **Severity**: info
- **Type**: unknown
- **Target**: unknown
- **Attack Technique**: T1190 - Exploit Public-Facing Application
- **OWASP**: A01:2021-Broken Access Control
- **CVSS**: 0.0 (Informational)

#### Description
Detect Operating System


#### Remediation
Apply input validation and least-privilege controls.


#### Proof of Concept / Evidence
```
[{"type": "nuclei_finding", "template": "smb-os-detect", "matched_at": "127.0.0.1:445", "url": "127.0.0.1:445", "request": "var m = require(\"nuclei/smb\");\nvar c = new m.SMBClient();\nvar response = c.ListSMBv2Metadata(Host, Port);\nif (response.OSVersion === \"6.3.9600\") {\n    osInfo = \"Windows 8.1\";\n} else if (response.OSVersion === \"3.10.511\") {\n    osInfo = \"Windows NT 3.1\";\n} else if (response.OSVersion === \"3.50.807\") {\n    osInfo = \"Windows NT 3.5\";\n} else if (response.OSVersion === \"3.10.528\") {\n    osInfo = \"Windows NT 3.1, Service Pack 3\";\n} else if (response.OSVersion === \"3.51.1057\") {\n    osInfo = \"Windows NT 3.51\";\n} else if (response.OSVersion === \"4.00.950\") {\n    osInfo = \"Windows 95\";\n} else if (response.OSVersion === \"4.00.950A\") {\n    osInfo = \"Windows 95 OEM Service Release 1\";\n} else if (response.OSVersion === \"4.00.950B\") {\n    osInfo = \"Windows 95 OEM Service Release 2\";\n} else if (response.OSVersion === \"4.0.1381\") {\n    osInfo = \"Windows NT 4.0\";\n} else if (response.OSVersion === \"4.00.950B\") {\n    osInfo = \"Windows 95 OEM Service Release 2.1\";\n} else if (response.OSVersion === \"4.00.950C\") {\n    osInfo = \"OEM Service Release 2.5\";\n} else if (response.OSVersion === \"4.10.1998\") {\n    osInfo = \"Windows 98\";\n} else if (response.OSVersion === \"4.10.2222\") {\n    osInfo = \"Windows 98 Second Edition (SE)\";\n} else if (response.OSVersion === \"5.0.2195\") {\n    osInfo = \"Windows 2000\";\n} else if (response.OSVersion === \"4.90.3000\") {\n    osInfo = \"Windows Me\";\n} else if (response.OSVersion === \"5.1.2600\") {\n    osInfo = \"Windows XP\";\n} else if (response.OSVersion === \"5.1.2600.1105-1106\") {\n    osInfo = \"Windows XP, Service Pack 1\";\n} else if (response.OSVersion === \"5.2.3790\") {\n    osInfo = \"Windows Server 2003\";\n} else if (response.OSVersion === \"5.1.2600.2180\") {\n    osInfo = \"Windows XP, Service Pack 2\";\n} else if (response.OSVersion === \"5.2.3790.1180\") {\n    osInfo = \"Windows Server 2003, Service Pack 1\";\n} else if (response.OSVersion === \"5.2.3790\") {\n    osInfo = \"Windows Server 2003 R2\";\n} else if (response.OSVersion === \"6.0.6000\") {\n    osInfo = \"Windows Vista\";\n} else if (response.OSVersion === \"5.2.3790\") {\n    osInfo = \"Windows Server 2003, Service Pack 2\";\n} else if (response.OSVersion === \"5.2.4500\") {\n    osInfo = \"Windows Home Server\";\n} else if (response.OSVersion === \"6.0.6001\") {\n    osInfo = \"Windows Vista, Service Pack 1\";\n} else if (response.OSVersion === \"6.0.6001\") {\n    osInfo = \"Windows Server 2008\";\n} else if (response.OSVersion === \"5.1.2600\") {\n    osInfo = \"Windows XP, Service Pack 3\";\n} else if (response.OSVersion === \"6.0.6002\") {\n    osInfo = \"Windows Vista, Service Pack 2\";\n} else if (response.OSVersion === \"6.0.6002\") {\n    osInfo = \"Windows Server 2008, Service Pack 2\";\n} else if (response.OSVersion === \"6.1.7600\") {\n    osInfo = \"Windows 7\";\n} else if (response.OSVersion === \"6.1.7600\") {\n    osInfo = \"Windows Server 2008 R2\";\n} else if (response.OSVersion === \"6.1.7601\") {\n    osInfo = \"Windows 7, Service Pack 1\";\n} else if (response.OSVersion === \"6.1.7601\") {\n    osInfo = \"Windows Server 2008 R2, Service Pack \";\n} else if (response.OSVersion === \"6.1.8400\") {\n    osInfo = \"Windows Home Server 2011\";\n} else if (response.OSVersion === \"6.2.9200\") {\n    osInfo = \"Windows Server 2012\";\n} else if (response.OSVersion === \"6.2.9200\") {\n    osInfo = \"Windows 8\";\n} else if (response.OSVersion === \"6.3.9600\") {\n    osInfo = \"Windows 8.1\";\n} else if (response.OSVersion === \"6.3.9600\") {\n    osInfo = \"Windows Server 2012 R2\";\n} else if (response.OSVersion === \"10.0.10240\") {\n    osInfo = \"Windows 10, Version 1507\";\n} else if (response.OSVersion === \"10.0.10586\") {\n    osInfo = \"Windows 10, Version 1511\";\n} else if (response.OSVersion === \"10.0

...[truncated 2701 chars — full evidence in the evidence vault; sha256 above covers the complete artifact]
```
**Artifact SHA-256 Hash**: `fc3ceaed9d3b031de6e93e3ea15b74c318ed3d0f1be5d68f8b274be9f347a0f0`
**Chain of Custody ID**: `no-audit-event`

---

### 20. smb2-capabilities - Enumeration
- **Severity**: info
- **Type**: unknown
- **Target**: unknown
- **Attack Technique**: T1190 - Exploit Public-Facing Application
- **OWASP**: A01:2021-Broken Access Control
- **CVSS**: 0.0 (Informational)

#### Description
Attempts to list the supported capabilities in a SMBv2 server for each enabled dialect.


#### Remediation
Apply input validation and least-privilege controls.


#### Proof of Concept / Evidence
```
[{"type": "nuclei_finding", "template": "smb2-capabilities", "matched_at": "127.0.0.1:445", "url": "127.0.0.1:445", "request": "var m = require(\"nuclei/smb\");\nvar c = m.SMBClient();\nvar response = c.ConnectSMBInfoMode(Host, Port);\nExport(response);", "response": "{\n  \"SupportV1\": false,\n  \"Version\": {\n    \"Major\": 2,\n    \"Minor\": 1,\n    \"Revision\": 0,\n    \"VerString\": \"SMB 2.1\"\n  },\n  \"NativeOs\": \"\",\n  \"NTLM\": \"\",\n  \"GroupName\": \"\",\n  \"Capabilities\": {\n    \"DFSSupport\": true,\n    \"Leasing\": true,\n    \"LargeMTU\": true,\n    \"MultiChan\": false,\n    \"Persist\": false,\n    \"DirLeasing\": false,\n    \"Encryption\": false\n  },\n  \"HasNTLM\": true,\n  \"NegotiationLog\": {\n    \"HeaderLog\": {\n      \"ProtocolID\": [\n        0,\n        0,\n        0,\n        0,\n        254,\n        83,\n        77,\n        66\n      ],\n      \"Status\": 0,\n      \"Command\": 0,\n      \"Credits\": 1,\n      \"Flags\": 1\n    },\n    \"ProtocolID\": [\n      0,\n      0,\n      0,\n      0,\n      254,\n      83,\n      77,\n      66\n    ],\n    \"Status\": 0,\n    \"Command\": 0,\n    \"Credits\": 1,\n    \"Flags\": 1,\n    \"SecurityMode\": 3,\n    \"DialectRevision\": 528,\n    \"ServerGuid\": [\n      0,\n      0,\n      0,\n      0,\n      0,\n      0,\n      0,\n      0,\n      0,\n      0,\n      0,\n      0,\n      0,\n      0,\n      0,\n      0,\n      244,\n      117,\n      7,\n      244,\n      85,\n      143,\n      174,\n      70,\n      151,\n      62,\n      59,\n      42,\n      30,\n      59,\n      134,\n      201\n    ],\n    \"Capabilities\": 7,\n    \"SystemTime\": 1788098756,\n    \"ServerStartTime\": 1240428288,\n    \"AuthenticationTypes\": [\n      \"1.3.6.1.4.1.311.2.2.30\",\n      \"1.3.6.1.4.1.311.2.2.10\"\n    ]\n  },\n  \"SessionSetupLog\": {\n    \"HeaderLog\": {\n      \"ProtocolID\": [\n        0,\n        0,\n        0,\n        0,\n        254,\n        83,\n        77,\n        66\n      ],\n      \"Status\": 3221225494,\n      \"Command\": 1,\n      \"Credits\": 1,\n      \"Flags\": 1\n    },\n    \"ProtocolID\": [\n      0,\n      0,\n      0,\n      0,\n      254,\n      83,\n      77,\n      66\n    ],\n    \"Status\": 3221225494,\n    \"Command\": 1,\n    \"Credits\": 1,\n    \"Flags\": 1,\n    \"SetupFlags\": 0,\n    \"TargetName\": \"DESKTOP-VJ5O45D\",\n    \"NegotiateFlags\": 2726953477\n  }\n}", "extracted_results": ["[\"DFSSupport\",\"LargeMTU\",\"Leasing\"]"], "false_positive_signal": {"out_of_scan_scope": true, "matched_endpoint": "127.0.0.1:445", "scoped_endpoints": ["127.0.0.1:80"], "reason": "nuclei matched a service on a host port this scan was not pointed at (shared-host service misattribution \u2014 real service, wrong engagement)"}}]
```
**Artifact SHA-256 Hash**: `c99789f8420b9ca49b2953db0edd078647f0dcbaebad47c093081166f094525e`
**Chain of Custody ID**: `no-audit-event`

---

### 21. PostgreSQL Authentication - Detect
- **Severity**: info
- **Type**: sqli
- **Target**: unknown
- **Attack Technique**: T1190 - Exploit Public-Facing Application
- **OWASP**: A03:2021-Injection
- **CVSS**: 0.0 (Informational)

#### Description
PostgreSQL authentication error messages which could reveal information useful in formulating further attacks were detected.


#### Remediation
Use parameterized queries / prepared statements; never concatenate input.


#### Proof of Concept / Evidence
```
[{"type": "nuclei_finding", "template": "pgsql-detect", "matched_at": "127.0.0.1:5432", "url": "127.0.0.1:5432", "request": "000000500003000075736572006e75636c6569006461746162617365006e75636c6569006170706c69636174696f6e5f6e616d65007073716c00636c69656e745f656e636f64696e67005554463800007000000036534352414d2d5348412d32353600000000206e2c2c6e3d2c723d000000000000000000000000000000000000000000000000", "response": "R\u0000\u0000\u0000\u0017\u0000\u0000\u0000\nSCRAM-SHA-256\u0000\u0000", "extracted_results": null, "false_positive_signal": {"out_of_scan_scope": true, "matched_endpoint": "127.0.0.1:5432", "scoped_endpoints": ["127.0.0.1:80"], "reason": "nuclei matched a service on a host port this scan was not pointed at (shared-host service misattribution \u2014 real service, wrong engagement)"}}]
```
**Artifact SHA-256 Hash**: `4b76f636758ab01db2362b5da7ae9bc02d3d2a5cc433c1604c54a35bda677ef8`
**Chain of Custody ID**: `no-audit-event`

---

### 22. FingerprintHub Technology Fingerprint
- **Severity**: info
- **Type**: unknown
- **Target**: unknown
- **Attack Technique**: T1190 - Exploit Public-Facing Application
- **OWASP**: A01:2021-Broken Access Control
- **CVSS**: 0.0 (Informational)

#### Description
FingerprintHub Technology Fingerprint tests run in nuclei.

#### Remediation
Apply input validation and least-privilege controls.


#### Proof of Concept / Evidence
```
[{"type": "nuclei_finding", "template": "fingerprinthub-web-fingerprints", "matched_at": "http://127.0.0.1/", "url": "http://127.0.0.1/", "request": "GET / HTTP/1.1\r\nHost: 127.0.0.1\r\nUser-Agent: Mozilla/5.0 (Ubuntu; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36\r\nConnection: close\r\nAccept: */*\r\nAccept-Language: en\r\nAccept-Encoding: gzip\r\n\r\n", "response": "HTTP/1.1 200 OK\r\nConnection: close\r\nTransfer-Encoding: chunked\r\nAccept-Ranges: bytes\r\nAccess-Control-Allow-Origin: *\r\nCache-Control: public, max-age=0\r\nContent-Type: text/html; charset=UTF-8\r\nDate: Sun, 30 Aug 2026 14:06:07 GMT\r\nEtag: W/\"26af-1a052fd9cd0\"\r\nFeature-Policy: payment 'self'\r\nLast-Modified: Sun, 30 Aug 2026 14:05:47 GMT\r\nVary: Accept-Encoding\r\nX-Content-Type-Options: nosniff\r\nX-Frame-Options: SAMEORIGIN\r\nX-Recruiting: /#/jobs\r\n\r\n<!--\n  ~ Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.\n  ~ SPDX-License-Identifier: MIT\n  -->\n\n<!doctype html>\n<html lang=\"en\" data-beasties-container>\n<head>\n  <meta charset=\"utf-8\">\n  <title>OWASP Juice Shop</title>\n  <meta name=\"description\" content=\"Probably the most modern and sophisticated insecure web application\">\n  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n  <link rel=\"preconnect\" href=\"https://fonts.googleapis.com\">\n  <link rel=\"preconnect\" href=\"https://fonts.gstatic.com\" crossorigin>\n  <style>@font-face{font-family:'VT323';font-style:normal;font-weight:400;font-display:swap;src:url(https://fonts.gstatic.com/s/vt323/v18/pxiKyp0ihIEF2isQFJXGdg.woff2) format('woff2');unicode-range:U+0102-0103, U+0110-0111, U+0128-0129, U+0168-0169, U+01A0-01A1, U+01AF-01B0, U+0300-0301, U+0303-0304, U+0308-0309, U+0323, U+0329, U+1EA0-1EF9, U+20AB;}@font-face{font-family:'VT323';font-style:normal;font-weight:400;font-display:swap;src:url(https://fonts.gstatic.com/s/vt323/v18/pxiKyp0ihIEF2isRFJXGdg.woff2) format('woff2');unicode-range:U+0100-02BA, U+02BD-02C5, U+02C7-02CC, U+02CE-02D7, U+02DD-02FF, U+0304, U+0308, U+0329, U+1D00-1DBF, U+1E00-1E9F, U+1EF2-1EFF, U+2020, U+20A0-20AB, U+20AD-20C0, U+2113, U+2C60-2C7F, U+A720-A7FF;}@font-face{font-family:'VT323';font-style:normal;font-weight:400;font-display:swap;src:url(https://fonts.gstatic.com/s/vt323/v18/pxiKyp0ihIEF2isfFJU.woff2) format('woff2');unicode-range:U+0000-00FF, U+0131, U+0152-0153, U+02BB-02BC, U+02C6, U+02DA, U+02DC, U+0304, U+0308, U+0329, U+2000-206F, U+20AC, U+2122, U+2191, U+2193, U+2212, U+2215, U+FEFF, U+FFFD;}</style>\n  <link id=\"favicon\" rel=\"icon\" type=\"image/x-icon\" href=\"assets/public/favicon_js.ico\">\n  <script>\n    window.addEventListener(\"load\", function(){\n      window.cookieconsent.initialise({\n        \"palette\": {\n          \"popup\": { \"background\": \"var(--theme-primary)\", \"text\": \"var(--theme-text)\" },\n          \"button\": { \"background\": \"var(--theme-accent)\", \"text\": \"var(--theme-text)\" }\n        },\n        \"theme\": \"classic\",\n        \"position\": \"bottom-right\",\n        \"content\": { \"message\": \"This website uses fruit cookies to ensure you get the juiciest tracking experience.\", \"dismiss\": \"Me want it!\", \"link\": \"But me wait!\", \"href\": \"https://www.youtube.com/watch?v=9PnbKL3wuH4\" }\n      })});\n  </script>\n<style>.bluegrey-lightgreen-theme{--mat-sys-background:#121316;--mat-sys-error:#ffb4ab;--mat-sys-error-container:#93000a;--mat-sys-inverse-on-surface:#2f3033;--mat-sys-inverse-primary:#005cbb;--mat-sys-inverse-surface:#e3e2e6;--mat-sys-on-background:#e3e2e6;--mat-sys-on-error:#690005;--mat-sys-on-error-container:#ffdad6;--mat-sys-on-primary:#002f65;--mat-sys-on-primary-container:#d7e3ff;--mat-sys-on-primary-fixed:#001b3f;--mat-sys-on-primary-fixed-variant:#00458f;--mat-sys-on-secondary:#283041;--mat-sys-on-secondary-container:#dae2f9;--mat-sys-on-secondary-fixed:#131c2b;--mat-sys-on-secondary-fixed-variant:#3e4759;--mat-

...[truncated 7167 chars — full evidence in the evidence vault; sha256 above covers the complete artifact]
```
**Artifact SHA-256 Hash**: `5e6c14d4db4b1cf870c82673a44bb4f77f330744d8fe453144b467576f8ec844`
**Chain of Custody ID**: `no-audit-event`

---

### 23. Wappalyzer Technology Detection
- **Severity**: info
- **Type**: unknown
- **Target**: unknown
- **Attack Technique**: T1190 - Exploit Public-Facing Application
- **OWASP**: A01:2021-Broken Access Control
- **CVSS**: 0.0 (Informational)

#### Description


#### Remediation
Apply input validation and least-privilege controls.


#### Proof of Concept / Evidence
```
[{"type": "nuclei_finding", "template": "tech-detect", "matched_at": "http://127.0.0.1/", "url": "http://127.0.0.1/", "request": "GET / HTTP/1.1\r\nHost: 127.0.0.1\r\nUser-Agent: Mozilla/5.0 (Ubuntu; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36\r\nConnection: close\r\nAccept: */*\r\nAccept-Language: en\r\nAccept-Encoding: gzip\r\n\r\n", "response": "HTTP/1.1 200 OK\r\nConnection: close\r\nTransfer-Encoding: chunked\r\nAccept-Ranges: bytes\r\nAccess-Control-Allow-Origin: *\r\nCache-Control: public, max-age=0\r\nContent-Type: text/html; charset=UTF-8\r\nDate: Sun, 30 Aug 2026 14:06:07 GMT\r\nEtag: W/\"26af-1a052fd9cd0\"\r\nFeature-Policy: payment 'self'\r\nLast-Modified: Sun, 30 Aug 2026 14:05:47 GMT\r\nVary: Accept-Encoding\r\nX-Content-Type-Options: nosniff\r\nX-Frame-Options: SAMEORIGIN\r\nX-Recruiting: /#/jobs\r\n\r\n<!--\n  ~ Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.\n  ~ SPDX-License-Identifier: MIT\n  -->\n\n<!doctype html>\n<html lang=\"en\" data-beasties-container>\n<head>\n  <meta charset=\"utf-8\">\n  <title>OWASP Juice Shop</title>\n  <meta name=\"description\" content=\"Probably the most modern and sophisticated insecure web application\">\n  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n  <link rel=\"preconnect\" href=\"https://fonts.googleapis.com\">\n  <link rel=\"preconnect\" href=\"https://fonts.gstatic.com\" crossorigin>\n  <style>@font-face{font-family:'VT323';font-style:normal;font-weight:400;font-display:swap;src:url(https://fonts.gstatic.com/s/vt323/v18/pxiKyp0ihIEF2isQFJXGdg.woff2) format('woff2');unicode-range:U+0102-0103, U+0110-0111, U+0128-0129, U+0168-0169, U+01A0-01A1, U+01AF-01B0, U+0300-0301, U+0303-0304, U+0308-0309, U+0323, U+0329, U+1EA0-1EF9, U+20AB;}@font-face{font-family:'VT323';font-style:normal;font-weight:400;font-display:swap;src:url(https://fonts.gstatic.com/s/vt323/v18/pxiKyp0ihIEF2isRFJXGdg.woff2) format('woff2');unicode-range:U+0100-02BA, U+02BD-02C5, U+02C7-02CC, U+02CE-02D7, U+02DD-02FF, U+0304, U+0308, U+0329, U+1D00-1DBF, U+1E00-1E9F, U+1EF2-1EFF, U+2020, U+20A0-20AB, U+20AD-20C0, U+2113, U+2C60-2C7F, U+A720-A7FF;}@font-face{font-family:'VT323';font-style:normal;font-weight:400;font-display:swap;src:url(https://fonts.gstatic.com/s/vt323/v18/pxiKyp0ihIEF2isfFJU.woff2) format('woff2');unicode-range:U+0000-00FF, U+0131, U+0152-0153, U+02BB-02BC, U+02C6, U+02DA, U+02DC, U+0304, U+0308, U+0329, U+2000-206F, U+20AC, U+2122, U+2191, U+2193, U+2212, U+2215, U+FEFF, U+FFFD;}</style>\n  <link id=\"favicon\" rel=\"icon\" type=\"image/x-icon\" href=\"assets/public/favicon_js.ico\">\n  <script>\n    window.addEventListener(\"load\", function(){\n      window.cookieconsent.initialise({\n        \"palette\": {\n          \"popup\": { \"background\": \"var(--theme-primary)\", \"text\": \"var(--theme-text)\" },\n          \"button\": { \"background\": \"var(--theme-accent)\", \"text\": \"var(--theme-text)\" }\n        },\n        \"theme\": \"classic\",\n        \"position\": \"bottom-right\",\n        \"content\": { \"message\": \"This website uses fruit cookies to ensure you get the juiciest tracking experience.\", \"dismiss\": \"Me want it!\", \"link\": \"But me wait!\", \"href\": \"https://www.youtube.com/watch?v=9PnbKL3wuH4\" }\n      })});\n  </script>\n<style>.bluegrey-lightgreen-theme{--mat-sys-background:#121316;--mat-sys-error:#ffb4ab;--mat-sys-error-container:#93000a;--mat-sys-inverse-on-surface:#2f3033;--mat-sys-inverse-primary:#005cbb;--mat-sys-inverse-surface:#e3e2e6;--mat-sys-on-background:#e3e2e6;--mat-sys-on-error:#690005;--mat-sys-on-error-container:#ffdad6;--mat-sys-on-primary:#002f65;--mat-sys-on-primary-container:#d7e3ff;--mat-sys-on-primary-fixed:#001b3f;--mat-sys-on-primary-fixed-variant:#00458f;--mat-sys-on-secondary:#283041;--mat-sys-on-secondary-container:#dae2f9;--mat-sys-on-secondary-fixed:#131c2b;--mat-sys-on-secondary-fixed-variant:#3e4759;--mat-sys-on-surface:#e3e2

...[truncated 7197 chars — full evidence in the evidence vault; sha256 above covers the complete artifact]
```
**Artifact SHA-256 Hash**: `afa717622b738dade845826ab734b33c8c947532d3dbb0170fb9b4dbf3449347`
**Chain of Custody ID**: `no-audit-event`

---

### 24. HTTP Missing Security Headers
- **Severity**: info
- **Type**: unknown
- **Target**: unknown
- **Attack Technique**: T1190 - Exploit Public-Facing Application
- **OWASP**: A01:2021-Broken Access Control
- **CVSS**: 0.0 (Informational)

#### Description
This template searches for missing HTTP security headers. The impact of these missing headers can vary.


#### Remediation
Apply input validation and least-privilege controls.


#### Proof of Concept / Evidence
```
[{"type": "nuclei_finding", "template": "http-missing-security-headers", "matched_at": "http://127.0.0.1/", "url": "http://127.0.0.1/", "request": "GET / HTTP/1.1\r\nHost: 127.0.0.1\r\nUser-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2.1 Safari/605.1.1\r\nConnection: close\r\nAccept: */*\r\nAccept-Language: en\r\nAccept-Encoding: gzip\r\n\r\n", "response": "HTTP/1.1 200 OK\r\nConnection: close\r\nTransfer-Encoding: chunked\r\nAccept-Ranges: bytes\r\nAccess-Control-Allow-Origin: *\r\nCache-Control: public, max-age=0\r\nContent-Type: text/html; charset=UTF-8\r\nDate: Sun, 30 Aug 2026 14:06:08 GMT\r\nEtag: W/\"26af-1a052fd9cd0\"\r\nFeature-Policy: payment 'self'\r\nLast-Modified: Sun, 30 Aug 2026 14:05:47 GMT\r\nVary: Accept-Encoding\r\nX-Content-Type-Options: nosniff\r\nX-Frame-Options: SAMEORIGIN\r\nX-Recruiting: /#/jobs\r\n\r\n<!--\n  ~ Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.\n  ~ SPDX-License-Identifier: MIT\n  -->\n\n<!doctype html>\n<html lang=\"en\" data-beasties-container>\n<head>\n  <meta charset=\"utf-8\">\n  <title>OWASP Juice Shop</title>\n  <meta name=\"description\" content=\"Probably the most modern and sophisticated insecure web application\">\n  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n  <link rel=\"preconnect\" href=\"https://fonts.googleapis.com\">\n  <link rel=\"preconnect\" href=\"https://fonts.gstatic.com\" crossorigin>\n  <style>@font-face{font-family:'VT323';font-style:normal;font-weight:400;font-display:swap;src:url(https://fonts.gstatic.com/s/vt323/v18/pxiKyp0ihIEF2isQFJXGdg.woff2) format('woff2');unicode-range:U+0102-0103, U+0110-0111, U+0128-0129, U+0168-0169, U+01A0-01A1, U+01AF-01B0, U+0300-0301, U+0303-0304, U+0308-0309, U+0323, U+0329, U+1EA0-1EF9, U+20AB;}@font-face{font-family:'VT323';font-style:normal;font-weight:400;font-display:swap;src:url(https://fonts.gstatic.com/s/vt323/v18/pxiKyp0ihIEF2isRFJXGdg.woff2) format('woff2');unicode-range:U+0100-02BA, U+02BD-02C5, U+02C7-02CC, U+02CE-02D7, U+02DD-02FF, U+0304, U+0308, U+0329, U+1D00-1DBF, U+1E00-1E9F, U+1EF2-1EFF, U+2020, U+20A0-20AB, U+20AD-20C0, U+2113, U+2C60-2C7F, U+A720-A7FF;}@font-face{font-family:'VT323';font-style:normal;font-weight:400;font-display:swap;src:url(https://fonts.gstatic.com/s/vt323/v18/pxiKyp0ihIEF2isfFJU.woff2) format('woff2');unicode-range:U+0000-00FF, U+0131, U+0152-0153, U+02BB-02BC, U+02C6, U+02DA, U+02DC, U+0304, U+0308, U+0329, U+2000-206F, U+20AC, U+2122, U+2191, U+2193, U+2212, U+2215, U+FEFF, U+FFFD;}</style>\n  <link id=\"favicon\" rel=\"icon\" type=\"image/x-icon\" href=\"assets/public/favicon_js.ico\">\n  <script>\n    window.addEventListener(\"load\", function(){\n      window.cookieconsent.initialise({\n        \"palette\": {\n          \"popup\": { \"background\": \"var(--theme-primary)\", \"text\": \"var(--theme-text)\" },\n          \"button\": { \"background\": \"var(--theme-accent)\", \"text\": \"var(--theme-text)\" }\n        },\n        \"theme\": \"classic\",\n        \"position\": \"bottom-right\",\n        \"content\": { \"message\": \"This website uses fruit cookies to ensure you get the juiciest tracking experience.\", \"dismiss\": \"Me want it!\", \"link\": \"But me wait!\", \"href\": \"https://www.youtube.com/watch?v=9PnbKL3wuH4\" }\n      })});\n  </script>\n<style>.bluegrey-lightgreen-theme{--mat-sys-background:#121316;--mat-sys-error:#ffb4ab;--mat-sys-error-container:#93000a;--mat-sys-inverse-on-surface:#2f3033;--mat-sys-inverse-primary:#005cbb;--mat-sys-inverse-surface:#e3e2e6;--mat-sys-on-background:#e3e2e6;--mat-sys-on-error:#690005;--mat-sys-on-error-container:#ffdad6;--mat-sys-on-primary:#002f65;--mat-sys-on-primary-container:#d7e3ff;--mat-sys-on-primary-fixed:#001b3f;--mat-sys-on-primary-fixed-variant:#00458f;--mat-sys-on-secondary:#283041;--mat-sys-on-secondary-container:#dae2f9;--mat-sys-on-secondary-fixed:#131c2b;--mat-sys-on-secondary-fixed-variant:#3

...[truncated 7179 chars — full evidence in the evidence vault; sha256 above covers the complete artifact]
```
**Artifact SHA-256 Hash**: `2fb7752bcb1c10eedbacde73bda9e0e8dd36a33afe3ff10c08c0ca14ea318840`
**Chain of Custody ID**: `no-audit-event`

---

### 25. X-Recruiting Header
- **Severity**: info
- **Type**: unknown
- **Target**: unknown
- **Attack Technique**: T1190 - Exploit Public-Facing Application
- **OWASP**: A01:2021-Broken Access Control
- **CVSS**: 0.0 (Informational)

#### Description
Websites that advertise jobs via HTTP headers

#### Remediation
Apply input validation and least-privilege controls.


#### Proof of Concept / Evidence
```
[{"type": "nuclei_finding", "template": "x-recruiting-header", "matched_at": "http://127.0.0.1/", "url": "http://127.0.0.1/", "request": "GET / HTTP/1.1\r\nHost: 127.0.0.1\r\nUser-Agent: Mozilla/5.0 (X11; Linux i686; rv:1.9.5.20) Gecko/ Firefox/10.0\r\nConnection: close\r\nAccept: */*\r\nAccept-Language: en\r\nAccept-Encoding: gzip\r\n\r\n", "response": "HTTP/1.1 200 OK\r\nConnection: close\r\nTransfer-Encoding: chunked\r\nAccept-Ranges: bytes\r\nAccess-Control-Allow-Origin: *\r\nCache-Control: public, max-age=0\r\nContent-Type: text/html; charset=UTF-8\r\nDate: Sun, 30 Aug 2026 14:06:16 GMT\r\nEtag: W/\"26af-1a052fd9cd0\"\r\nFeature-Policy: payment 'self'\r\nLast-Modified: Sun, 30 Aug 2026 14:05:47 GMT\r\nVary: Accept-Encoding\r\nX-Content-Type-Options: nosniff\r\nX-Frame-Options: SAMEORIGIN\r\nX-Recruiting: /#/jobs\r\n\r\n<!--\n  ~ Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.\n  ~ SPDX-License-Identifier: MIT\n  -->\n\n<!doctype html>\n<html lang=\"en\" data-beasties-container>\n<head>\n  <meta charset=\"utf-8\">\n  <title>OWASP Juice Shop</title>\n  <meta name=\"description\" content=\"Probably the most modern and sophisticated insecure web application\">\n  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n  <link rel=\"preconnect\" href=\"https://fonts.googleapis.com\">\n  <link rel=\"preconnect\" href=\"https://fonts.gstatic.com\" crossorigin>\n  <style>@font-face{font-family:'VT323';font-style:normal;font-weight:400;font-display:swap;src:url(https://fonts.gstatic.com/s/vt323/v18/pxiKyp0ihIEF2isQFJXGdg.woff2) format('woff2');unicode-range:U+0102-0103, U+0110-0111, U+0128-0129, U+0168-0169, U+01A0-01A1, U+01AF-01B0, U+0300-0301, U+0303-0304, U+0308-0309, U+0323, U+0329, U+1EA0-1EF9, U+20AB;}@font-face{font-family:'VT323';font-style:normal;font-weight:400;font-display:swap;src:url(https://fonts.gstatic.com/s/vt323/v18/pxiKyp0ihIEF2isRFJXGdg.woff2) format('woff2');unicode-range:U+0100-02BA, U+02BD-02C5, U+02C7-02CC, U+02CE-02D7, U+02DD-02FF, U+0304, U+0308, U+0329, U+1D00-1DBF, U+1E00-1E9F, U+1EF2-1EFF, U+2020, U+20A0-20AB, U+20AD-20C0, U+2113, U+2C60-2C7F, U+A720-A7FF;}@font-face{font-family:'VT323';font-style:normal;font-weight:400;font-display:swap;src:url(https://fonts.gstatic.com/s/vt323/v18/pxiKyp0ihIEF2isfFJU.woff2) format('woff2');unicode-range:U+0000-00FF, U+0131, U+0152-0153, U+02BB-02BC, U+02C6, U+02DA, U+02DC, U+0304, U+0308, U+0329, U+2000-206F, U+20AC, U+2122, U+2191, U+2193, U+2212, U+2215, U+FEFF, U+FFFD;}</style>\n  <link id=\"favicon\" rel=\"icon\" type=\"image/x-icon\" href=\"assets/public/favicon_js.ico\">\n  <script>\n    window.addEventListener(\"load\", function(){\n      window.cookieconsent.initialise({\n        \"palette\": {\n          \"popup\": { \"background\": \"var(--theme-primary)\", \"text\": \"var(--theme-text)\" },\n          \"button\": { \"background\": \"var(--theme-accent)\", \"text\": \"var(--theme-text)\" }\n        },\n        \"theme\": \"classic\",\n        \"position\": \"bottom-right\",\n        \"content\": { \"message\": \"This website uses fruit cookies to ensure you get the juiciest tracking experience.\", \"dismiss\": \"Me want it!\", \"link\": \"But me wait!\", \"href\": \"https://www.youtube.com/watch?v=9PnbKL3wuH4\" }\n      })});\n  </script>\n<style>.bluegrey-lightgreen-theme{--mat-sys-background:#121316;--mat-sys-error:#ffb4ab;--mat-sys-error-container:#93000a;--mat-sys-inverse-on-surface:#2f3033;--mat-sys-inverse-primary:#005cbb;--mat-sys-inverse-surface:#e3e2e6;--mat-sys-on-background:#e3e2e6;--mat-sys-on-error:#690005;--mat-sys-on-error-container:#ffdad6;--mat-sys-on-primary:#002f65;--mat-sys-on-primary-container:#d7e3ff;--mat-sys-on-primary-fixed:#001b3f;--mat-sys-on-primary-fixed-variant:#00458f;--mat-sys-on-secondary:#283041;--mat-sys-on-secondary-container:#dae2f9;--mat-sys-on-secondary-fixed:#131c2b;--mat-sys-on-secondary-fixed-variant:#3e4759;--mat-sys-on-surface:#e3e2e6;--mat-sys-on-surface-variant:#e

...[truncated 7120 chars — full evidence in the evidence vault; sha256 above covers the complete artifact]
```
**Artifact SHA-256 Hash**: `eb6459b36cba7996dfbeb7219cdb82dc7d101df3f5b7b76bfa48ceef67a344ee`
**Chain of Custody ID**: `no-audit-event`

---

### 26. Add DOM EventListener - Detection
- **Severity**: info
- **Type**: unknown
- **Target**: unknown
- **Attack Technique**: T1190 - Exploit Public-Facing Application
- **OWASP**: A01:2021-Broken Access Control
- **CVSS**: 0.0 (Informational)

#### Description
Identifies the use of JavaScript addEventListener calls in the DOM.


#### Remediation
Apply input validation and least-privilege controls.


#### Proof of Concept / Evidence
```
[{"type": "nuclei_finding", "template": "addeventlistener-detect", "matched_at": "http://127.0.0.1/", "url": "http://127.0.0.1/", "request": "GET / HTTP/1.1\r\nHost: 127.0.0.1\r\nUser-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 12_5) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.4 Safari/605.1.15\r\nConnection: close\r\nAccept: */*\r\nAccept-Language: en\r\nAccept-Encoding: gzip\r\n\r\n", "response": "HTTP/1.1 200 OK\r\nConnection: close\r\nTransfer-Encoding: chunked\r\nAccept-Ranges: bytes\r\nAccess-Control-Allow-Origin: *\r\nCache-Control: public, max-age=0\r\nContent-Type: text/html; charset=UTF-8\r\nDate: Sun, 30 Aug 2026 14:06:30 GMT\r\nEtag: W/\"26af-1a052fd9cd0\"\r\nFeature-Policy: payment 'self'\r\nLast-Modified: Sun, 30 Aug 2026 14:05:47 GMT\r\nVary: Accept-Encoding\r\nX-Content-Type-Options: nosniff\r\nX-Frame-Options: SAMEORIGIN\r\nX-Recruiting: /#/jobs\r\n\r\n<!--\n  ~ Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.\n  ~ SPDX-License-Identifier: MIT\n  -->\n\n<!doctype html>\n<html lang=\"en\" data-beasties-container>\n<head>\n  <meta charset=\"utf-8\">\n  <title>OWASP Juice Shop</title>\n  <meta name=\"description\" content=\"Probably the most modern and sophisticated insecure web application\">\n  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n  <link rel=\"preconnect\" href=\"https://fonts.googleapis.com\">\n  <link rel=\"preconnect\" href=\"https://fonts.gstatic.com\" crossorigin>\n  <style>@font-face{font-family:'VT323';font-style:normal;font-weight:400;font-display:swap;src:url(https://fonts.gstatic.com/s/vt323/v18/pxiKyp0ihIEF2isQFJXGdg.woff2) format('woff2');unicode-range:U+0102-0103, U+0110-0111, U+0128-0129, U+0168-0169, U+01A0-01A1, U+01AF-01B0, U+0300-0301, U+0303-0304, U+0308-0309, U+0323, U+0329, U+1EA0-1EF9, U+20AB;}@font-face{font-family:'VT323';font-style:normal;font-weight:400;font-display:swap;src:url(https://fonts.gstatic.com/s/vt323/v18/pxiKyp0ihIEF2isRFJXGdg.woff2) format('woff2');unicode-range:U+0100-02BA, U+02BD-02C5, U+02C7-02CC, U+02CE-02D7, U+02DD-02FF, U+0304, U+0308, U+0329, U+1D00-1DBF, U+1E00-1E9F, U+1EF2-1EFF, U+2020, U+20A0-20AB, U+20AD-20C0, U+2113, U+2C60-2C7F, U+A720-A7FF;}@font-face{font-family:'VT323';font-style:normal;font-weight:400;font-display:swap;src:url(https://fonts.gstatic.com/s/vt323/v18/pxiKyp0ihIEF2isfFJU.woff2) format('woff2');unicode-range:U+0000-00FF, U+0131, U+0152-0153, U+02BB-02BC, U+02C6, U+02DA, U+02DC, U+0304, U+0308, U+0329, U+2000-206F, U+20AC, U+2122, U+2191, U+2193, U+2212, U+2215, U+FEFF, U+FFFD;}</style>\n  <link id=\"favicon\" rel=\"icon\" type=\"image/x-icon\" href=\"assets/public/favicon_js.ico\">\n  <script>\n    window.addEventListener(\"load\", function(){\n      window.cookieconsent.initialise({\n        \"palette\": {\n          \"popup\": { \"background\": \"var(--theme-primary)\", \"text\": \"var(--theme-text)\" },\n          \"button\": { \"background\": \"var(--theme-accent)\", \"text\": \"var(--theme-text)\" }\n        },\n        \"theme\": \"classic\",\n        \"position\": \"bottom-right\",\n        \"content\": { \"message\": \"This website uses fruit cookies to ensure you get the juiciest tracking experience.\", \"dismiss\": \"Me want it!\", \"link\": \"But me wait!\", \"href\": \"https://www.youtube.com/watch?v=9PnbKL3wuH4\" }\n      })});\n  </script>\n<style>.bluegrey-lightgreen-theme{--mat-sys-background:#121316;--mat-sys-error:#ffb4ab;--mat-sys-error-container:#93000a;--mat-sys-inverse-on-surface:#2f3033;--mat-sys-inverse-primary:#005cbb;--mat-sys-inverse-surface:#e3e2e6;--mat-sys-on-background:#e3e2e6;--mat-sys-on-error:#690005;--mat-sys-on-error-container:#ffdad6;--mat-sys-on-primary:#002f65;--mat-sys-on-primary-container:#d7e3ff;--mat-sys-on-primary-fixed:#001b3f;--mat-sys-on-primary-fixed-variant:#00458f;--mat-sys-on-secondary:#283041;--mat-sys-on-secondary-container:#dae2f9;--mat-sys-on-secondary-fixed:#131c2b;--mat-sys-on-secondary-fixed-variant:#3e4759;--ma

...[truncated 7231 chars — full evidence in the evidence vault; sha256 above covers the complete artifact]
```
**Artifact SHA-256 Hash**: `239b3964a3d96f02d03237425f3382534feac43cec3231ddb98e6aec25169f0d`
**Chain of Custody ID**: `no-audit-event`

---

### 27. Deprecated Feature-Policy Header - Detection
- **Severity**: info
- **Type**: unknown
- **Target**: unknown
- **Attack Technique**: T1190 - Exploit Public-Facing Application
- **OWASP**: A01:2021-Broken Access Control
- **CVSS**: 0.0 (Informational)

#### Description
Detected the presence of the deprecated Feature-Policy HTTP response header. The Feature-Policy header has been deprecated and replaced by the Permissions-Policy header. While Feature-Policy is still supported in some browsers for backward compatibility, it is recommended to migrate to Permissions-Policy for future-proofing web applications.


#### Remediation
Apply input validation and least-privilege controls.


#### Proof of Concept / Evidence
```
[{"type": "nuclei_finding", "template": "deprecated-feature-policy", "matched_at": "http://127.0.0.1/", "url": "http://127.0.0.1/", "request": "GET / HTTP/1.1\r\nHost: 127.0.0.1\r\nUser-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 12_5) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.4 Safari/605.1.15\r\nConnection: close\r\nAccept: */*\r\nAccept-Language: en\r\nAccept-Encoding: gzip\r\n\r\n", "response": "HTTP/1.1 200 OK\r\nConnection: close\r\nTransfer-Encoding: chunked\r\nAccept-Ranges: bytes\r\nAccess-Control-Allow-Origin: *\r\nCache-Control: public, max-age=0\r\nContent-Type: text/html; charset=UTF-8\r\nDate: Sun, 30 Aug 2026 14:06:30 GMT\r\nEtag: W/\"26af-1a052fd9cd0\"\r\nFeature-Policy: payment 'self'\r\nLast-Modified: Sun, 30 Aug 2026 14:05:47 GMT\r\nVary: Accept-Encoding\r\nX-Content-Type-Options: nosniff\r\nX-Frame-Options: SAMEORIGIN\r\nX-Recruiting: /#/jobs\r\n\r\n<!--\n  ~ Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.\n  ~ SPDX-License-Identifier: MIT\n  -->\n\n<!doctype html>\n<html lang=\"en\" data-beasties-container>\n<head>\n  <meta charset=\"utf-8\">\n  <title>OWASP Juice Shop</title>\n  <meta name=\"description\" content=\"Probably the most modern and sophisticated insecure web application\">\n  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n  <link rel=\"preconnect\" href=\"https://fonts.googleapis.com\">\n  <link rel=\"preconnect\" href=\"https://fonts.gstatic.com\" crossorigin>\n  <style>@font-face{font-family:'VT323';font-style:normal;font-weight:400;font-display:swap;src:url(https://fonts.gstatic.com/s/vt323/v18/pxiKyp0ihIEF2isQFJXGdg.woff2) format('woff2');unicode-range:U+0102-0103, U+0110-0111, U+0128-0129, U+0168-0169, U+01A0-01A1, U+01AF-01B0, U+0300-0301, U+0303-0304, U+0308-0309, U+0323, U+0329, U+1EA0-1EF9, U+20AB;}@font-face{font-family:'VT323';font-style:normal;font-weight:400;font-display:swap;src:url(https://fonts.gstatic.com/s/vt323/v18/pxiKyp0ihIEF2isRFJXGdg.woff2) format('woff2');unicode-range:U+0100-02BA, U+02BD-02C5, U+02C7-02CC, U+02CE-02D7, U+02DD-02FF, U+0304, U+0308, U+0329, U+1D00-1DBF, U+1E00-1E9F, U+1EF2-1EFF, U+2020, U+20A0-20AB, U+20AD-20C0, U+2113, U+2C60-2C7F, U+A720-A7FF;}@font-face{font-family:'VT323';font-style:normal;font-weight:400;font-display:swap;src:url(https://fonts.gstatic.com/s/vt323/v18/pxiKyp0ihIEF2isfFJU.woff2) format('woff2');unicode-range:U+0000-00FF, U+0131, U+0152-0153, U+02BB-02BC, U+02C6, U+02DA, U+02DC, U+0304, U+0308, U+0329, U+2000-206F, U+20AC, U+2122, U+2191, U+2193, U+2212, U+2215, U+FEFF, U+FFFD;}</style>\n  <link id=\"favicon\" rel=\"icon\" type=\"image/x-icon\" href=\"assets/public/favicon_js.ico\">\n  <script>\n    window.addEventListener(\"load\", function(){\n      window.cookieconsent.initialise({\n        \"palette\": {\n          \"popup\": { \"background\": \"var(--theme-primary)\", \"text\": \"var(--theme-text)\" },\n          \"button\": { \"background\": \"var(--theme-accent)\", \"text\": \"var(--theme-text)\" }\n        },\n        \"theme\": \"classic\",\n        \"position\": \"bottom-right\",\n        \"content\": { \"message\": \"This website uses fruit cookies to ensure you get the juiciest tracking experience.\", \"dismiss\": \"Me want it!\", \"link\": \"But me wait!\", \"href\": \"https://www.youtube.com/watch?v=9PnbKL3wuH4\" }\n      })});\n  </script>\n<style>.bluegrey-lightgreen-theme{--mat-sys-background:#121316;--mat-sys-error:#ffb4ab;--mat-sys-error-container:#93000a;--mat-sys-inverse-on-surface:#2f3033;--mat-sys-inverse-primary:#005cbb;--mat-sys-inverse-surface:#e3e2e6;--mat-sys-on-background:#e3e2e6;--mat-sys-on-error:#690005;--mat-sys-on-error-container:#ffdad6;--mat-sys-on-primary:#002f65;--mat-sys-on-primary-container:#d7e3ff;--mat-sys-on-primary-fixed:#001b3f;--mat-sys-on-primary-fixed-variant:#00458f;--mat-sys-on-secondary:#283041;--mat-sys-on-secondary-container:#dae2f9;--mat-sys-on-secondary-fixed:#131c2b;--mat-sys-on-secondary-fixed-variant:#3e4759;--

...[truncated 7185 chars — full evidence in the evidence vault; sha256 above covers the complete artifact]
```
**Artifact SHA-256 Hash**: `dcf9a1a217fa4086b9b60339b0ee3da21e38b2891f84deef389e3d3775b8029f`
**Chain of Custody ID**: `no-audit-event`

---

### 28. OWASP Juice Shop
- **Severity**: info
- **Type**: unknown
- **Target**: unknown
- **Attack Technique**: T1190 - Exploit Public-Facing Application
- **OWASP**: A01:2021-Broken Access Control
- **CVSS**: 0.0 (Informational)

#### Description


#### Remediation
Apply input validation and least-privilege controls.


#### Proof of Concept / Evidence
```
[{"type": "nuclei_finding", "template": "owasp-juice-shop-detect", "matched_at": "http://127.0.0.1/", "url": "http://127.0.0.1/", "request": "GET / HTTP/1.1\r\nHost: 127.0.0.1\r\nUser-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 12_5) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.4 Safari/605.1.15\r\nConnection: close\r\nAccept: */*\r\nAccept-Language: en\r\nAccept-Encoding: gzip\r\n\r\n", "response": "HTTP/1.1 200 OK\r\nConnection: close\r\nTransfer-Encoding: chunked\r\nAccept-Ranges: bytes\r\nAccess-Control-Allow-Origin: *\r\nCache-Control: public, max-age=0\r\nContent-Type: text/html; charset=UTF-8\r\nDate: Sun, 30 Aug 2026 14:06:30 GMT\r\nEtag: W/\"26af-1a052fd9cd0\"\r\nFeature-Policy: payment 'self'\r\nLast-Modified: Sun, 30 Aug 2026 14:05:47 GMT\r\nVary: Accept-Encoding\r\nX-Content-Type-Options: nosniff\r\nX-Frame-Options: SAMEORIGIN\r\nX-Recruiting: /#/jobs\r\n\r\n<!--\n  ~ Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.\n  ~ SPDX-License-Identifier: MIT\n  -->\n\n<!doctype html>\n<html lang=\"en\" data-beasties-container>\n<head>\n  <meta charset=\"utf-8\">\n  <title>OWASP Juice Shop</title>\n  <meta name=\"description\" content=\"Probably the most modern and sophisticated insecure web application\">\n  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n  <link rel=\"preconnect\" href=\"https://fonts.googleapis.com\">\n  <link rel=\"preconnect\" href=\"https://fonts.gstatic.com\" crossorigin>\n  <style>@font-face{font-family:'VT323';font-style:normal;font-weight:400;font-display:swap;src:url(https://fonts.gstatic.com/s/vt323/v18/pxiKyp0ihIEF2isQFJXGdg.woff2) format('woff2');unicode-range:U+0102-0103, U+0110-0111, U+0128-0129, U+0168-0169, U+01A0-01A1, U+01AF-01B0, U+0300-0301, U+0303-0304, U+0308-0309, U+0323, U+0329, U+1EA0-1EF9, U+20AB;}@font-face{font-family:'VT323';font-style:normal;font-weight:400;font-display:swap;src:url(https://fonts.gstatic.com/s/vt323/v18/pxiKyp0ihIEF2isRFJXGdg.woff2) format('woff2');unicode-range:U+0100-02BA, U+02BD-02C5, U+02C7-02CC, U+02CE-02D7, U+02DD-02FF, U+0304, U+0308, U+0329, U+1D00-1DBF, U+1E00-1E9F, U+1EF2-1EFF, U+2020, U+20A0-20AB, U+20AD-20C0, U+2113, U+2C60-2C7F, U+A720-A7FF;}@font-face{font-family:'VT323';font-style:normal;font-weight:400;font-display:swap;src:url(https://fonts.gstatic.com/s/vt323/v18/pxiKyp0ihIEF2isfFJU.woff2) format('woff2');unicode-range:U+0000-00FF, U+0131, U+0152-0153, U+02BB-02BC, U+02C6, U+02DA, U+02DC, U+0304, U+0308, U+0329, U+2000-206F, U+20AC, U+2122, U+2191, U+2193, U+2212, U+2215, U+FEFF, U+FFFD;}</style>\n  <link id=\"favicon\" rel=\"icon\" type=\"image/x-icon\" href=\"assets/public/favicon_js.ico\">\n  <script>\n    window.addEventListener(\"load\", function(){\n      window.cookieconsent.initialise({\n        \"palette\": {\n          \"popup\": { \"background\": \"var(--theme-primary)\", \"text\": \"var(--theme-text)\" },\n          \"button\": { \"background\": \"var(--theme-accent)\", \"text\": \"var(--theme-text)\" }\n        },\n        \"theme\": \"classic\",\n        \"position\": \"bottom-right\",\n        \"content\": { \"message\": \"This website uses fruit cookies to ensure you get the juiciest tracking experience.\", \"dismiss\": \"Me want it!\", \"link\": \"But me wait!\", \"href\": \"https://www.youtube.com/watch?v=9PnbKL3wuH4\" }\n      })});\n  </script>\n<style>.bluegrey-lightgreen-theme{--mat-sys-background:#121316;--mat-sys-error:#ffb4ab;--mat-sys-error-container:#93000a;--mat-sys-inverse-on-surface:#2f3033;--mat-sys-inverse-primary:#005cbb;--mat-sys-inverse-surface:#e3e2e6;--mat-sys-on-background:#e3e2e6;--mat-sys-on-error:#690005;--mat-sys-on-error-container:#ffdad6;--mat-sys-on-primary:#002f65;--mat-sys-on-primary-container:#d7e3ff;--mat-sys-on-primary-fixed:#001b3f;--mat-sys-on-primary-fixed-variant:#00458f;--mat-sys-on-secondary:#283041;--mat-sys-on-secondary-container:#dae2f9;--mat-sys-on-secondary-fixed:#131c2b;--mat-sys-on-secondary-fixed-variant:#3e4759;--ma

...[truncated 7231 chars — full evidence in the evidence vault; sha256 above covers the complete artifact]
```
**Artifact SHA-256 Hash**: `3c396909346d2cef86608b1bdd96b9587d3bea2fef065e5c01b61980ea821d2f`
**Chain of Custody ID**: `no-audit-event`

---
