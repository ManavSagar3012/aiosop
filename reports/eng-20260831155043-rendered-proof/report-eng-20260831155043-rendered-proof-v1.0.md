# CONFIDENTIAL / CLIENT-SENSITIVE
# Executive Summary
**Engagement ID:** eng-20260831155043-rendered-proof
**Date Generated:** 2026-08-31
**Version:** v1.0

## Risk Narrative
**CONFIDENTIAL**

**Executive Risk Narrative — Engagement eng-20260831155043-rendered-proof**

The assessment identified 32 total findings across a single in-scope asset and nine evaluated endpoints, of which 10 (31%) are rated High or Critical — a concentration of severity that places the environment at an elevated overall risk posture. Most concerning are two Critical vulnerabilities in the Redis deployment: an integer overflow in Lua script handling affecting versions prior to 8.2.1, and a use-after-free condition in the Lua parser prior to 8.2.2. Both are memory-corruption flaws in a service that frequently handles untrusted input, and either could be leveraged for remote code execution or service compromise. Compounding this, confirmed SQL injection was demonstrated in the authentication parameters (`username` and `password`) of the web application, a finding class that directly threatens credential integrity and exposes the backend data store to unauthorized access, enumeration, or manipulation.

From a business perspective, the combination of exploitable infrastructure flaws and injection defects in the authentication path represents a realistic path from external access to full system compromise, and these should be treated as the immediate remediation priority. We recommend upgrading Redis to version 8.2.2 or later without delay, remediating the SQL injection defects through parameterized queries and input validation, and addressing the confirmed reflected cross-site scripting issue in the `to` GET parameter (Medium) as part of the same remediation cycle. The remaining 20 informational findings, while not individually urgent, should be reviewed for systemic weaknesses in configuration and coding practice. Following remediation, a focused retest of the affected components is advised to validate closure of the Critical and High findings before the risk posture can be considered acceptable.

**CONFIDENTIAL**

## Assessment Overview
- **Total Assets Discovered:** 1
- **Total Endpoints Mapped:** 9
- **Critical Vulnerabilities:** 2
- **High Vulnerabilities:** 8

## Key Findings Summary

- **medium**: XSS via GET parameter 'to' (web_audit differential) (xss)

- **high**: SQLI via POST parameter 'username' (web_audit differential) (sqli)

- **high**: SQLI via POST parameter 'password' (web_audit differential) (sqli)

- **critical**: Redis < 8.2.1 lua script - Integer Overflow (rce)

- **critical**: Redis Lua Parser < 8.2.2 - Use After Free (rce)


# CONFIDENTIAL / CLIENT-SENSITIVE
# Technical Details
**Engagement ID:** eng-20260831155043-rendered-proof

## Verified Vulnerabilities


### 1. XSS via GET parameter 'to' (web_audit differential)
- **Severity**: medium
- **Type**: xss
- **Target**: unknown
- **Attack Technique**: T1059.007 - Command and Scripting Interpreter: JavaScript
- **OWASP**: A03:2021-Injection
- **CVSS**: 5.4 (Medium)

#### Description
web_audit differential confirmed XSS at http://127.0.0.1/redirect?to=https://github.com/juice-shop/juice-shop: GET parameter 'to' with probe '<script>probe_xss_marker_9f3a</script>' produced a behavioral delta the control request lacked (error_signature=True, auth_bypass=False).

#### Remediation
Context-aware output encoding; a strict CSP; avoid innerHTML with untrusted data.


#### Proof of Concept / Evidence
```
[{"type": "web_audit_differential", "provenance": "web_audit", "url": "http://127.0.0.1/redirect?to=https://github.com/juice-shop/juice-shop", "method": "GET", "parameter": "to", "baseline_value": "audit_probe_baseline_77", "probe": "<script>probe_xss_marker_9f3a</script>", "baseline_status": 406, "injected_status": 406, "error_signature": true, "auth_bypass": false, "authenticated": false}]
```
**Artifact SHA-256 Hash**: `08ad30f7db2dd395fcc8f9e882522f435043771ffb3d95413ba25d554b1355b8`
**Chain of Custody ID**: `no-audit-event`

---

### 2. SQLI via POST parameter 'username' (web_audit differential)
- **Severity**: high
- **Type**: sqli
- **Target**: unknown
- **Attack Technique**: T1190 - Exploit Public-Facing Application
- **OWASP**: A03:2021-Injection
- **CVSS**: 8.1 (High)

#### Description
web_audit differential confirmed SQLI at http://127.0.0.1:9199/login: POST parameter 'username' with probe "' OR '1'='1' --" produced a behavioral delta the control request lacked (error_signature=False, auth_bypass=True).

#### Remediation
Use parameterized queries / prepared statements; never concatenate input.


#### Proof of Concept / Evidence
```
[{"type": "web_audit_differential", "provenance": "web_audit", "url": "http://127.0.0.1:9199/login", "method": "POST", "parameter": "username", "baseline_value": "audit_probe_baseline_77", "probe": "' OR '1'='1' --", "baseline_status": 401, "injected_status": 200, "error_signature": false, "auth_bypass": true, "authenticated": false}]
```
**Artifact SHA-256 Hash**: `9b1257d4de7426d2d3c649bdbbaca57d80e70822e7a11e1ee3f4c9ba179f9895`
**Chain of Custody ID**: `no-audit-event`

---

### 3. SQLI via POST parameter 'password' (web_audit differential)
- **Severity**: high
- **Type**: sqli
- **Target**: unknown
- **Attack Technique**: T1190 - Exploit Public-Facing Application
- **OWASP**: A03:2021-Injection
- **CVSS**: 8.1 (High)

#### Description
web_audit differential confirmed SQLI at http://127.0.0.1:9199/login: POST parameter 'password' with probe "' OR '1'='1" produced a behavioral delta the control request lacked (error_signature=False, auth_bypass=True).

#### Remediation
Use parameterized queries / prepared statements; never concatenate input.


#### Proof of Concept / Evidence
```
[{"type": "web_audit_differential", "provenance": "web_audit", "url": "http://127.0.0.1:9199/login", "method": "POST", "parameter": "password", "baseline_value": "audit_probe_baseline_77", "probe": "' OR '1'='1", "baseline_status": 401, "injected_status": 200, "error_signature": false, "auth_bypass": true, "authenticated": false}]
```
**Artifact SHA-256 Hash**: `59ed63b3ab69d203a95d3cae5350fd29901db6132e1da32981ac1cafe21c468e`
**Chain of Custody ID**: `no-audit-event`

---

### 4. Redis < 8.2.1 lua script - Integer Overflow
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
[{"type": "nuclei_finding", "template": "CVE-2025-46817", "matched_at": "127.0.0.1:6379", "url": "127.0.0.1:6379", "request": "const redis = require('nuclei/redis');\nconst info = redis.GetServerInfo(Host, Port);\nExport(info);", "response": "# Server\r\nredis_version:7.0.15\r\nredis_git_sha1:00000000\r\nredis_git_dirty:0\r\nredis_build_id:e53ff17674aa6190\r\nredis_mode:standalone\r\nos:Linux 6.6.87.2-microsoft-standard-WSL2 x86_64\r\narch_bits:64\r\nmonotonic_clock:POSIX clock_gettime\r\nmultiplexing_api:epoll\r\natomicvar_api:c11-builtin\r\ngcc_version:13.3.0\r\nprocess_id:183\r\nprocess_supervised:systemd\r\nrun_id:c7b80a33478526d60213ef2ca0a4a997767f1f96\r\ntcp_port:6379\r\nserver_time_usec:1788191737005847\r\nuptime_in_seconds:38679\r\nuptime_in_days:0\r\nhz:10\r\nconfigured_hz:10\r\nlru_clock:9806840\r\nexecutable:/usr/bin/redis-server\r\nconfig_file:/etc/redis/redis.conf\r\nio_threads_active:0\r\n\r\n# Clients\r\nconnected_clients:1\r\ncluster_connections:0\r\nmaxclients:10000\r\nclient_recent_max_input_buffer:0\r\nclient_recent_max_output_buffer:0\r\nblocked_clients:0\r\ntracking_clients:0\r\nclients_in_timeout_table:0\r\n\r\n# Memory\r\nused_memory:1191024\r\nused_memory_human:1.14M\r\nused_memory_rss:13762560\r\nused_memory_rss_human:13.12M\r\nused_memory_peak:1191024\r\nused_memory_peak_human:1.14M\r\nused_memory_peak_perc:100.21%\r\nused_memory_overhead:879576\r\nused_memory_startup:876272\r\nused_memory_dataset:311448\r\nused_memory_dataset_perc:98.95%\r\nallocator_allocated:1670672\r\nallocator_active:1994752\r\nallocator_resident:6787072\r\ntotal_system_memory:8153911296\r\ntotal_system_memory_human:7.59G\r\nused_memory_lua:31744\r\nused_memory_vm_eval:31744\r\nused_memory_lua_human:31.00K\r\nused_memory_scripts_eval:0\r\nnumber_of_cached_scripts:0\r\nnumber_of_functions:0\r\nnumber_of_libraries:0\r\nused_memory_vm_functions:32768\r\nused_memory_vm_total:64512\r\nused_memory_vm_total_human:63.00K\r\nused_memory_functions:200\r\nused_memory_scripts:200\r\nused_memory_scripts_human:200B\r\nmaxmemory:0\r\nmaxmemory_human:0B\r\nmaxmemory_policy:noeviction\r\nallocator_frag_ratio:1.19\r\nallocator_frag_bytes:324080\r\nallocator_rss_ratio:3.40\r\nallocator_rss_bytes:4792320\r\nrss_overhead_ratio:2.03\r\nrss_overhead_bytes:6975488\r\nmem_fragmentation_ratio:12.50\r\nmem_fragmentation_bytes:12661544\r\nmem_not_counted_for_evict:0\r\nmem_replication_backlog:0\r\nmem_total_replication_buffers:0\r\nmem_clients_slaves:0\r\nmem_clients_normal:0\r\nmem_cluster_links:0\r\nmem_aof_buffer:0\r\nmem_allocator:jemalloc-5.3.0\r\nactive_defrag_running:0\r\nlazyfree_pending_objects:0\r\nlazyfreed_objects:0\r\n\r\n# Persistence\r\nloading:0\r\nasync_loading:0\r\ncurrent_cow_peak:0\r\ncurrent_cow_size:0\r\ncurrent_cow_size_age:0\r\ncurrent_fork_perc:0.00\r\ncurrent_save_keys_processed:0\r\ncurrent_save_keys_total:0\r\nrdb_changes_since_last_save:0\r\nrdb_bgsave_in_progress:0\r\nrdb_last_save_time:1788153058\r\nrdb_last_bgsave_status:ok\r\nrdb_last_bgsave_time_sec:-1\r\nrdb_current_bgsave_time_sec:-1\r\nrdb_saves:0\r\nrdb_last_cow_size:0\r\nrdb_last_load_keys_expired:0\r\nrdb_last_load_keys_loaded:64\r\naof_enabled:0\r\naof_rewrite_in_progress:0\r\naof_rewrite_scheduled:0\r\naof_last_rewrite_time_sec:-1\r\naof_current_rewrite_time_sec:-1\r\naof_last_bgrewrite_status:ok\r\naof_rewrites:0\r\naof_rewrites_consecutive_failures:0\r\naof_last_write_status:ok\r\naof_last_cow_size:0\r\nmodule_fork_in_progress:0\r\nmodule_fork_last_cow_size:0\r\n\r\n# Stats\r\ntotal_connections_received:10\r\ntotal_commands_processed:2\r\ninstantaneous_ops_per_sec:0\r\ntotal_net_input_bytes:174\r\ntotal_net_output_bytes:259\r\ntotal_net_repl_input_bytes:0\r\ntotal_net_repl_output_bytes:0\r\ninstantaneous_input_kbps:0.00\r\ninstantaneous_output_kbps:0.00\r\ninstantaneous_input_repl_kbps:0.00\r\ninstantaneous_output_repl_kbps:0.00\r\nrejected_connections:0\r\nsync_full:0\r\nsync_partial_ok:0\r\nsync_partial_err:0\r\nexpired_keys:0\r\nexpired_stale_perc:0.00\r\nexpi

...[truncated 1962 chars — full evidence in the evidence vault; sha256 above covers the complete artifact]
```
**Artifact SHA-256 Hash**: `b59938422e16d07a54a757a81a186567be2f3fe977a96b7a609074bf30c3692c`
**Chain of Custody ID**: `no-audit-event`

---

### 5. Redis Lua Parser < 8.2.2 - Use After Free
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
[{"type": "nuclei_finding", "template": "CVE-2025-49844", "matched_at": "127.0.0.1:6379", "url": "127.0.0.1:6379", "request": "const redis = require('nuclei/redis');\nconst info = redis.GetServerInfo(Host, Port);\nExport(info);", "response": "# Server\r\nredis_version:7.0.15\r\nredis_git_sha1:00000000\r\nredis_git_dirty:0\r\nredis_build_id:e53ff17674aa6190\r\nredis_mode:standalone\r\nos:Linux 6.6.87.2-microsoft-standard-WSL2 x86_64\r\narch_bits:64\r\nmonotonic_clock:POSIX clock_gettime\r\nmultiplexing_api:epoll\r\natomicvar_api:c11-builtin\r\ngcc_version:13.3.0\r\nprocess_id:183\r\nprocess_supervised:systemd\r\nrun_id:c7b80a33478526d60213ef2ca0a4a997767f1f96\r\ntcp_port:6379\r\nserver_time_usec:1788191737005847\r\nuptime_in_seconds:38679\r\nuptime_in_days:0\r\nhz:10\r\nconfigured_hz:10\r\nlru_clock:9806840\r\nexecutable:/usr/bin/redis-server\r\nconfig_file:/etc/redis/redis.conf\r\nio_threads_active:0\r\n\r\n# Clients\r\nconnected_clients:1\r\ncluster_connections:0\r\nmaxclients:10000\r\nclient_recent_max_input_buffer:0\r\nclient_recent_max_output_buffer:0\r\nblocked_clients:0\r\ntracking_clients:0\r\nclients_in_timeout_table:0\r\n\r\n# Memory\r\nused_memory:1191024\r\nused_memory_human:1.14M\r\nused_memory_rss:13762560\r\nused_memory_rss_human:13.12M\r\nused_memory_peak:1191024\r\nused_memory_peak_human:1.14M\r\nused_memory_peak_perc:100.21%\r\nused_memory_overhead:879576\r\nused_memory_startup:876272\r\nused_memory_dataset:311448\r\nused_memory_dataset_perc:98.95%\r\nallocator_allocated:1670672\r\nallocator_active:1994752\r\nallocator_resident:6787072\r\ntotal_system_memory:8153911296\r\ntotal_system_memory_human:7.59G\r\nused_memory_lua:31744\r\nused_memory_vm_eval:31744\r\nused_memory_lua_human:31.00K\r\nused_memory_scripts_eval:0\r\nnumber_of_cached_scripts:0\r\nnumber_of_functions:0\r\nnumber_of_libraries:0\r\nused_memory_vm_functions:32768\r\nused_memory_vm_total:64512\r\nused_memory_vm_total_human:63.00K\r\nused_memory_functions:200\r\nused_memory_scripts:200\r\nused_memory_scripts_human:200B\r\nmaxmemory:0\r\nmaxmemory_human:0B\r\nmaxmemory_policy:noeviction\r\nallocator_frag_ratio:1.19\r\nallocator_frag_bytes:324080\r\nallocator_rss_ratio:3.40\r\nallocator_rss_bytes:4792320\r\nrss_overhead_ratio:2.03\r\nrss_overhead_bytes:6975488\r\nmem_fragmentation_ratio:12.50\r\nmem_fragmentation_bytes:12661544\r\nmem_not_counted_for_evict:0\r\nmem_replication_backlog:0\r\nmem_total_replication_buffers:0\r\nmem_clients_slaves:0\r\nmem_clients_normal:0\r\nmem_cluster_links:0\r\nmem_aof_buffer:0\r\nmem_allocator:jemalloc-5.3.0\r\nactive_defrag_running:0\r\nlazyfree_pending_objects:0\r\nlazyfreed_objects:0\r\n\r\n# Persistence\r\nloading:0\r\nasync_loading:0\r\ncurrent_cow_peak:0\r\ncurrent_cow_size:0\r\ncurrent_cow_size_age:0\r\ncurrent_fork_perc:0.00\r\ncurrent_save_keys_processed:0\r\ncurrent_save_keys_total:0\r\nrdb_changes_since_last_save:0\r\nrdb_bgsave_in_progress:0\r\nrdb_last_save_time:1788153058\r\nrdb_last_bgsave_status:ok\r\nrdb_last_bgsave_time_sec:-1\r\nrdb_current_bgsave_time_sec:-1\r\nrdb_saves:0\r\nrdb_last_cow_size:0\r\nrdb_last_load_keys_expired:0\r\nrdb_last_load_keys_loaded:64\r\naof_enabled:0\r\naof_rewrite_in_progress:0\r\naof_rewrite_scheduled:0\r\naof_last_rewrite_time_sec:-1\r\naof_current_rewrite_time_sec:-1\r\naof_last_bgrewrite_status:ok\r\naof_rewrites:0\r\naof_rewrites_consecutive_failures:0\r\naof_last_write_status:ok\r\naof_last_cow_size:0\r\nmodule_fork_in_progress:0\r\nmodule_fork_last_cow_size:0\r\n\r\n# Stats\r\ntotal_connections_received:10\r\ntotal_commands_processed:2\r\ninstantaneous_ops_per_sec:0\r\ntotal_net_input_bytes:174\r\ntotal_net_output_bytes:259\r\ntotal_net_repl_input_bytes:0\r\ntotal_net_repl_output_bytes:0\r\ninstantaneous_input_kbps:0.00\r\ninstantaneous_output_kbps:0.00\r\ninstantaneous_input_repl_kbps:0.00\r\ninstantaneous_output_repl_kbps:0.00\r\nrejected_connections:0\r\nsync_full:0\r\nsync_partial_ok:0\r\nsync_partial_err:0\r\nexpired_keys:0\r\nexpired_stale_perc:0.00\r\nexpi

...[truncated 1962 chars — full evidence in the evidence vault; sha256 above covers the complete artifact]
```
**Artifact SHA-256 Hash**: `ee19e5fa9644b84b56b8b9f36c116e6d85f9f46bb8852ab69d0f90e3bd084f53`
**Chain of Custody ID**: `no-audit-event`

---

### 6. Redis Lua Sandbox < 8.2.2 - Cross-User Escape
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
[{"type": "nuclei_finding", "template": "CVE-2025-46818", "matched_at": "127.0.0.1:6379", "url": "127.0.0.1:6379", "request": "const redis = require('nuclei/redis');\nconst info = redis.GetServerInfo(Host, Port);\nExport(info);", "response": "# Server\r\nredis_version:7.0.15\r\nredis_git_sha1:00000000\r\nredis_git_dirty:0\r\nredis_build_id:e53ff17674aa6190\r\nredis_mode:standalone\r\nos:Linux 6.6.87.2-microsoft-standard-WSL2 x86_64\r\narch_bits:64\r\nmonotonic_clock:POSIX clock_gettime\r\nmultiplexing_api:epoll\r\natomicvar_api:c11-builtin\r\ngcc_version:13.3.0\r\nprocess_id:183\r\nprocess_supervised:systemd\r\nrun_id:c7b80a33478526d60213ef2ca0a4a997767f1f96\r\ntcp_port:6379\r\nserver_time_usec:1788191737005847\r\nuptime_in_seconds:38679\r\nuptime_in_days:0\r\nhz:10\r\nconfigured_hz:10\r\nlru_clock:9806840\r\nexecutable:/usr/bin/redis-server\r\nconfig_file:/etc/redis/redis.conf\r\nio_threads_active:0\r\n\r\n# Clients\r\nconnected_clients:1\r\ncluster_connections:0\r\nmaxclients:10000\r\nclient_recent_max_input_buffer:0\r\nclient_recent_max_output_buffer:0\r\nblocked_clients:0\r\ntracking_clients:0\r\nclients_in_timeout_table:0\r\n\r\n# Memory\r\nused_memory:1191024\r\nused_memory_human:1.14M\r\nused_memory_rss:13762560\r\nused_memory_rss_human:13.12M\r\nused_memory_peak:1191024\r\nused_memory_peak_human:1.14M\r\nused_memory_peak_perc:100.21%\r\nused_memory_overhead:879576\r\nused_memory_startup:876272\r\nused_memory_dataset:311448\r\nused_memory_dataset_perc:98.95%\r\nallocator_allocated:1670672\r\nallocator_active:1994752\r\nallocator_resident:6787072\r\ntotal_system_memory:8153911296\r\ntotal_system_memory_human:7.59G\r\nused_memory_lua:31744\r\nused_memory_vm_eval:31744\r\nused_memory_lua_human:31.00K\r\nused_memory_scripts_eval:0\r\nnumber_of_cached_scripts:0\r\nnumber_of_functions:0\r\nnumber_of_libraries:0\r\nused_memory_vm_functions:32768\r\nused_memory_vm_total:64512\r\nused_memory_vm_total_human:63.00K\r\nused_memory_functions:200\r\nused_memory_scripts:200\r\nused_memory_scripts_human:200B\r\nmaxmemory:0\r\nmaxmemory_human:0B\r\nmaxmemory_policy:noeviction\r\nallocator_frag_ratio:1.19\r\nallocator_frag_bytes:324080\r\nallocator_rss_ratio:3.40\r\nallocator_rss_bytes:4792320\r\nrss_overhead_ratio:2.03\r\nrss_overhead_bytes:6975488\r\nmem_fragmentation_ratio:12.50\r\nmem_fragmentation_bytes:12661544\r\nmem_not_counted_for_evict:0\r\nmem_replication_backlog:0\r\nmem_total_replication_buffers:0\r\nmem_clients_slaves:0\r\nmem_clients_normal:0\r\nmem_cluster_links:0\r\nmem_aof_buffer:0\r\nmem_allocator:jemalloc-5.3.0\r\nactive_defrag_running:0\r\nlazyfree_pending_objects:0\r\nlazyfreed_objects:0\r\n\r\n# Persistence\r\nloading:0\r\nasync_loading:0\r\ncurrent_cow_peak:0\r\ncurrent_cow_size:0\r\ncurrent_cow_size_age:0\r\ncurrent_fork_perc:0.00\r\ncurrent_save_keys_processed:0\r\ncurrent_save_keys_total:0\r\nrdb_changes_since_last_save:0\r\nrdb_bgsave_in_progress:0\r\nrdb_last_save_time:1788153058\r\nrdb_last_bgsave_status:ok\r\nrdb_last_bgsave_time_sec:-1\r\nrdb_current_bgsave_time_sec:-1\r\nrdb_saves:0\r\nrdb_last_cow_size:0\r\nrdb_last_load_keys_expired:0\r\nrdb_last_load_keys_loaded:64\r\naof_enabled:0\r\naof_rewrite_in_progress:0\r\naof_rewrite_scheduled:0\r\naof_last_rewrite_time_sec:-1\r\naof_current_rewrite_time_sec:-1\r\naof_last_bgrewrite_status:ok\r\naof_rewrites:0\r\naof_rewrites_consecutive_failures:0\r\naof_last_write_status:ok\r\naof_last_cow_size:0\r\nmodule_fork_in_progress:0\r\nmodule_fork_last_cow_size:0\r\n\r\n# Stats\r\ntotal_connections_received:10\r\ntotal_commands_processed:2\r\ninstantaneous_ops_per_sec:0\r\ntotal_net_input_bytes:174\r\ntotal_net_output_bytes:259\r\ntotal_net_repl_input_bytes:0\r\ntotal_net_repl_output_bytes:0\r\ninstantaneous_input_kbps:0.00\r\ninstantaneous_output_kbps:0.00\r\ninstantaneous_input_repl_kbps:0.00\r\ninstantaneous_output_repl_kbps:0.00\r\nrejected_connections:0\r\nsync_full:0\r\nsync_partial_ok:0\r\nsync_partial_err:0\r\nexpired_keys:0\r\nexpired_stale_perc:0.00\r\nexpi

...[truncated 1962 chars — full evidence in the evidence vault; sha256 above covers the complete artifact]
```
**Artifact SHA-256 Hash**: `85f31985b0dabf21bef4765378656b7092dfa589a1a9114a06cb844b9c5daf78`
**Chain of Custody ID**: `no-audit-event`

---

### 7. Redis  < 8.2.1 Lua Long-String Delimiter - Out-of-Bounds Read
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
[{"type": "nuclei_finding", "template": "CVE-2025-46819", "matched_at": "127.0.0.1:6379", "url": "127.0.0.1:6379", "request": "const redis = require('nuclei/redis');\nconst info = redis.GetServerInfo(Host, Port);\nExport(info);", "response": "# Server\r\nredis_version:7.0.15\r\nredis_git_sha1:00000000\r\nredis_git_dirty:0\r\nredis_build_id:e53ff17674aa6190\r\nredis_mode:standalone\r\nos:Linux 6.6.87.2-microsoft-standard-WSL2 x86_64\r\narch_bits:64\r\nmonotonic_clock:POSIX clock_gettime\r\nmultiplexing_api:epoll\r\natomicvar_api:c11-builtin\r\ngcc_version:13.3.0\r\nprocess_id:183\r\nprocess_supervised:systemd\r\nrun_id:c7b80a33478526d60213ef2ca0a4a997767f1f96\r\ntcp_port:6379\r\nserver_time_usec:1788191737005847\r\nuptime_in_seconds:38679\r\nuptime_in_days:0\r\nhz:10\r\nconfigured_hz:10\r\nlru_clock:9806840\r\nexecutable:/usr/bin/redis-server\r\nconfig_file:/etc/redis/redis.conf\r\nio_threads_active:0\r\n\r\n# Clients\r\nconnected_clients:1\r\ncluster_connections:0\r\nmaxclients:10000\r\nclient_recent_max_input_buffer:0\r\nclient_recent_max_output_buffer:0\r\nblocked_clients:0\r\ntracking_clients:0\r\nclients_in_timeout_table:0\r\n\r\n# Memory\r\nused_memory:1191024\r\nused_memory_human:1.14M\r\nused_memory_rss:13762560\r\nused_memory_rss_human:13.12M\r\nused_memory_peak:1191024\r\nused_memory_peak_human:1.14M\r\nused_memory_peak_perc:100.21%\r\nused_memory_overhead:879576\r\nused_memory_startup:876272\r\nused_memory_dataset:311448\r\nused_memory_dataset_perc:98.95%\r\nallocator_allocated:1670672\r\nallocator_active:1994752\r\nallocator_resident:6787072\r\ntotal_system_memory:8153911296\r\ntotal_system_memory_human:7.59G\r\nused_memory_lua:31744\r\nused_memory_vm_eval:31744\r\nused_memory_lua_human:31.00K\r\nused_memory_scripts_eval:0\r\nnumber_of_cached_scripts:0\r\nnumber_of_functions:0\r\nnumber_of_libraries:0\r\nused_memory_vm_functions:32768\r\nused_memory_vm_total:64512\r\nused_memory_vm_total_human:63.00K\r\nused_memory_functions:200\r\nused_memory_scripts:200\r\nused_memory_scripts_human:200B\r\nmaxmemory:0\r\nmaxmemory_human:0B\r\nmaxmemory_policy:noeviction\r\nallocator_frag_ratio:1.19\r\nallocator_frag_bytes:324080\r\nallocator_rss_ratio:3.40\r\nallocator_rss_bytes:4792320\r\nrss_overhead_ratio:2.03\r\nrss_overhead_bytes:6975488\r\nmem_fragmentation_ratio:12.50\r\nmem_fragmentation_bytes:12661544\r\nmem_not_counted_for_evict:0\r\nmem_replication_backlog:0\r\nmem_total_replication_buffers:0\r\nmem_clients_slaves:0\r\nmem_clients_normal:0\r\nmem_cluster_links:0\r\nmem_aof_buffer:0\r\nmem_allocator:jemalloc-5.3.0\r\nactive_defrag_running:0\r\nlazyfree_pending_objects:0\r\nlazyfreed_objects:0\r\n\r\n# Persistence\r\nloading:0\r\nasync_loading:0\r\ncurrent_cow_peak:0\r\ncurrent_cow_size:0\r\ncurrent_cow_size_age:0\r\ncurrent_fork_perc:0.00\r\ncurrent_save_keys_processed:0\r\ncurrent_save_keys_total:0\r\nrdb_changes_since_last_save:0\r\nrdb_bgsave_in_progress:0\r\nrdb_last_save_time:1788153058\r\nrdb_last_bgsave_status:ok\r\nrdb_last_bgsave_time_sec:-1\r\nrdb_current_bgsave_time_sec:-1\r\nrdb_saves:0\r\nrdb_last_cow_size:0\r\nrdb_last_load_keys_expired:0\r\nrdb_last_load_keys_loaded:64\r\naof_enabled:0\r\naof_rewrite_in_progress:0\r\naof_rewrite_scheduled:0\r\naof_last_rewrite_time_sec:-1\r\naof_current_rewrite_time_sec:-1\r\naof_last_bgrewrite_status:ok\r\naof_rewrites:0\r\naof_rewrites_consecutive_failures:0\r\naof_last_write_status:ok\r\naof_last_cow_size:0\r\nmodule_fork_in_progress:0\r\nmodule_fork_last_cow_size:0\r\n\r\n# Stats\r\ntotal_connections_received:10\r\ntotal_commands_processed:2\r\ninstantaneous_ops_per_sec:0\r\ntotal_net_input_bytes:174\r\ntotal_net_output_bytes:259\r\ntotal_net_repl_input_bytes:0\r\ntotal_net_repl_output_bytes:0\r\ninstantaneous_input_kbps:0.00\r\ninstantaneous_output_kbps:0.00\r\ninstantaneous_input_repl_kbps:0.00\r\ninstantaneous_output_repl_kbps:0.00\r\nrejected_connections:0\r\nsync_full:0\r\nsync_partial_ok:0\r\nsync_partial_err:0\r\nexpired_keys:0\r\nexpired_stale_perc:0.00\r\nexpi

...[truncated 1962 chars — full evidence in the evidence vault; sha256 above covers the complete artifact]
```
**Artifact SHA-256 Hash**: `b17809ca0d156bef4652cea263aaba0181c0b2b69b2bd3a9725d49a76896b829`
**Chain of Custody ID**: `no-audit-event`

---

### 8. Redis - Default Logins
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
[{"type": "nuclei_finding", "template": "redis-default-logins", "matched_at": "127.0.0.1:6379", "url": "127.0.0.1:6379", "request": "var m = require(\"nuclei/redis\");\nm.GetServerInfoAuth(Host, Port, Password);", "response": "# Server\r\nredis_version:7.0.15\r\nredis_git_sha1:00000000\r\nredis_git_dirty:0\r\nredis_build_id:e53ff17674aa6190\r\nredis_mode:standalone\r\nos:Linux 6.6.87.2-microsoft-standard-WSL2 x86_64\r\narch_bits:64\r\nmonotonic_clock:POSIX clock_gettime\r\nmultiplexing_api:epoll\r\natomicvar_api:c11-builtin\r\ngcc_version:13.3.0\r\nprocess_id:183\r\nprocess_supervised:systemd\r\nrun_id:c7b80a33478526d60213ef2ca0a4a997767f1f96\r\ntcp_port:6379\r\nserver_time_usec:1788191737143410\r\nuptime_in_seconds:38679\r\nuptime_in_days:0\r\nhz:10\r\nconfigured_hz:10\r\nlru_clock:9806841\r\nexecutable:/usr/bin/redis-server\r\nconfig_file:/etc/redis/redis.conf\r\nio_threads_active:0\r\n\r\n# Clients\r\nconnected_clients:1\r\ncluster_connections:0\r\nmaxclients:10000\r\nclient_recent_max_input_buffer:0\r\nclient_recent_max_output_buffer:0\r\nblocked_clients:0\r\ntracking_clients:0\r\nclients_in_timeout_table:0\r\n\r\n# Memory\r\nused_memory:1240576\r\nused_memory_human:1.18M\r\nused_memory_rss:14024704\r\nused_memory_rss_human:13.38M\r\nused_memory_peak:1353208\r\nused_memory_peak_human:1.29M\r\nused_memory_peak_perc:91.68%\r\nused_memory_overhead:879728\r\nused_memory_startup:876272\r\nused_memory_dataset:360848\r\nused_memory_dataset_perc:99.05%\r\nallocator_allocated:1836688\r\nallocator_active:2170880\r\nallocator_resident:7036928\r\ntotal_system_memory:8153911296\r\ntotal_system_memory_human:7.59G\r\nused_memory_lua:32768\r\nused_memory_vm_eval:32768\r\nused_memory_lua_human:32.00K\r\nused_memory_scripts_eval:152\r\nnumber_of_cached_scripts:1\r\nnumber_of_functions:0\r\nnumber_of_libraries:0\r\nused_memory_vm_functions:32768\r\nused_memory_vm_total:65536\r\nused_memory_vm_total_human:64.00K\r\nused_memory_functions:200\r\nused_memory_scripts:352\r\nused_memory_scripts_human:352B\r\nmaxmemory:0\r\nmaxmemory_human:0B\r\nmaxmemory_policy:noeviction\r\nallocator_frag_ratio:1.18\r\nallocator_frag_bytes:334192\r\nallocator_rss_ratio:3.24\r\nallocator_rss_bytes:4866048\r\nrss_overhead_ratio:1.99\r\nrss_overhead_bytes:6987776\r\nmem_fragmentation_ratio:11.68\r\nmem_fragmentation_bytes:12824040\r\nmem_not_counted_for_evict:0\r\nmem_replication_backlog:0\r\nmem_total_replication_buffers:0\r\nmem_clients_slaves:0\r\nmem_clients_normal:0\r\nmem_cluster_links:0\r\nmem_aof_buffer:0\r\nmem_allocator:jemalloc-5.3.0\r\nactive_defrag_running:0\r\nlazyfree_pending_objects:0\r\nlazyfreed_objects:0\r\n\r\n# Persistence\r\nloading:0\r\nasync_loading:0\r\ncurrent_cow_peak:0\r\ncurrent_cow_size:0\r\ncurrent_cow_size_age:0\r\ncurrent_fork_perc:0.00\r\ncurrent_save_keys_processed:0\r\ncurrent_save_keys_total:0\r\nrdb_changes_since_last_save:0\r\nrdb_bgsave_in_progress:0\r\nrdb_last_save_time:1788153058\r\nrdb_last_bgsave_status:ok\r\nrdb_last_bgsave_time_sec:-1\r\nrdb_current_bgsave_time_sec:-1\r\nrdb_saves:0\r\nrdb_last_cow_size:0\r\nrdb_last_load_keys_expired:0\r\nrdb_last_load_keys_loaded:64\r\naof_enabled:0\r\naof_rewrite_in_progress:0\r\naof_rewrite_scheduled:0\r\naof_last_rewrite_time_sec:-1\r\naof_current_rewrite_time_sec:-1\r\naof_last_bgrewrite_status:ok\r\naof_rewrites:0\r\naof_rewrites_consecutive_failures:0\r\naof_last_write_status:ok\r\naof_last_cow_size:0\r\nmodule_fork_in_progress:0\r\nmodule_fork_last_cow_size:0\r\n\r\n# Stats\r\ntotal_connections_received:16\r\ntotal_commands_processed:17\r\ninstantaneous_ops_per_sec:9\r\ntotal_net_input_bytes:1212\r\ntotal_net_output_bytes:6627\r\ntotal_net_repl_input_bytes:0\r\ntotal_net_repl_output_bytes:0\r\ninstantaneous_input_kbps:0.60\r\ninstantaneous_output_kbps:3.85\r\ninstantaneous_input_repl_kbps:0.00\r\ninstantaneous_output_repl_kbps:0.00\r\nrejected_connections:0\r\nsync_full:0\r\nsync_partial_ok:0\r\nsync_partial_err:0\r\nexpired_keys:0\r\nexpired_stale_perc:0.00\r\nexpired_time_cap

...[truncated 1947 chars — full evidence in the evidence vault; sha256 above covers the complete artifact]
```
**Artifact SHA-256 Hash**: `e2de0b716f01e7c9e618a2c94706563d79dcd5b2c2d2eca09a6686aef94d5a7f`
**Chain of Custody ID**: `no-audit-event`

---

### 9. Redis Server - Unauthenticated Access
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
[{"type": "nuclei_finding", "template": "exposed-redis", "matched_at": "127.0.0.1:6379", "url": "127.0.0.1:6379", "request": "info\r\nquit\r\n", "response": "$5006\r\n# Server\r\nredis_version:7.0.15\r\nredis_git_sha1:00000000\r\nredis_git_dirty:0\r\nredis_build_id:e53ff17674aa6190\r\nredis_mode:standalone\r\nos:Linux 6.6.87.2-microsoft-standard-WSL2 x86_64\r\narch_bits:64\r\nmonotonic_clock:POSIX clock_gettime\r\nmultiplexing_api:epoll\r\natomicvar_api:c11-builtin\r\ngcc_version:13.3.0\r\nprocess_id:183\r\nprocess_supervised:systemd\r\nrun_id:c7b80a33478526d60213ef2ca0a4a997767f1f96\r\ntcp_port:6379\r\nserver_time_usec:1788191738010148\r\nuptime_in_seconds:38680\r\nuptime_in_days:0\r\nhz:10\r\nconfigured_hz:10\r\nlru_clock:9806841\r\nexecutable:/usr/bin/redis-server\r\nconfig_file:/etc/redis/redis.conf\r\nio_threads_active:0\r\n\r\n# Clients\r\nconnected_clients:2\r\ncluster_connections:0\r\nmaxclients:10000\r\nclient_recent_max_input_buffer:20524\r\nclient_recent_max_output_buffer:0\r\nblocked_clients:0\r\ntracking_clients:0\r\nclients_in_timeout_table:0\r\n\r\n# Memory\r\nused_memory:1263416\r\nused_memory_human:1.20M\r\nused_memory_rss:14024704\r\nused_memory_rss_human:13.38M\r\nused_memory_peak:1353208\r\nused_memory_peak_human:1.29M\r\nused_memory_peak_perc:93.36%\r\nused_memory_overhead:902028\r\nused_memory_startup:876272\r\nused_memory_dataset:361388\r\nused_memory_dataset_perc:93.35%\r\nallocator_allocated:1837088\r\nallocator_active:2174976\r\nallocator_resident:7036928\r\ntotal_system_memory:8153911296\r\ntotal_system_memory_human:7.59G\r\nused_memory_lua:32768\r\nused_memory_vm_eval:32768\r\nused_memory_lua_human:32.00K\r\nused_memory_scripts_eval:152\r\nnumber_of_cached_scripts:1\r\nnumber_of_functions:0\r\nnumber_of_libraries:0\r\nused_memory_vm_functions:32768\r\nused_memory_vm_total:65536\r\nused_memory_vm_total_human:64.00K\r\nused_memory_functions:200\r\nused_memory_scripts:352\r\nused_memory_scripts_human:352B\r\nmaxmemory:0\r\nmaxmemory_human:0B\r\nmaxmemory_policy:noeviction\r\nallocator_frag_ratio:1.18\r\nallocator_frag_bytes:337888\r\nallocator_rss_ratio:3.24\r\nallocator_rss_bytes:4861952\r\nrss_overhead_ratio:1.99\r\nrss_overhead_bytes:6987776\r\nmem_fragmentation_ratio:11.46\r\nmem_fragmentation_bytes:12801224\r\nmem_not_counted_for_evict:0\r\nmem_replication_backlog:0\r\nmem_total_replication_buff", "extracted_results": null, "false_positive_signal": {"out_of_scan_scope": true, "matched_endpoint": "127.0.0.1:6379", "scoped_endpoints": ["127.0.0.1:80"], "reason": "nuclei matched a service on a host port this scan was not pointed at (shared-host service misattribution \u2014 real service, wrong engagement)"}}]
```
**Artifact SHA-256 Hash**: `ec9d374ff1f0b7fd0b747ce3f21051864da8491a4ac575a127668663469ab267`
**Chain of Custody ID**: `no-audit-event`

---

### 10. Prometheus Metrics - Detect
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
[{"type": "nuclei_finding", "template": "prometheus-metrics", "matched_at": "http://127.0.0.1/metrics", "url": "http://127.0.0.1/", "request": "GET /metrics HTTP/1.1\r\nHost: 127.0.0.1\r\nUser-Agent: Mozilla/5.0 (Windows NT 6.2; Win64; x64; rv:109.0) Gecko/20100101 Firefox/113.0\r\nConnection: close\r\nAccept: */*\r\nAccept-Language: en\r\nAccept-Encoding: gzip\r\n\r\n", "response": "HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: 25568\r\nContent-Type: text/plain; version=0.0.4; charset=utf-8\r\nDate: Mon, 31 Aug 2026 15:55:56 GMT\r\n\r\n# HELP juiceshop_llm_input_tokens_total Number of total input tokens processed\n# TYPE juiceshop_llm_input_tokens_total counter\njuiceshop_llm_input_tokens_total{app=\"juiceshop\"} 0\n\n# HELP juiceshop_llm_input_tokens Number of input tokens processed\n# TYPE juiceshop_llm_input_tokens counter\n\n# HELP juiceshop_llm_output_tokens_total Number of total output tokens processed\n# TYPE juiceshop_llm_output_tokens_total counter\njuiceshop_llm_output_tokens_total{app=\"juiceshop\"} 0\n\n# HELP juiceshop_llm_output_tokens Number of output tokens processed\n# TYPE juiceshop_llm_output_tokens counter\n\n# HELP juiceshop_llm_tool_calls_total Number of tool calls made\n# TYPE juiceshop_llm_tool_calls_total counter\n\n# HELP file_uploads_count Total number of successful file uploads grouped by file type.\n# TYPE file_uploads_count counter\n\n# HELP file_upload_errors Total number of failed file uploads grouped by file type.\n# TYPE file_upload_errors counter\n\n# HELP http_requests_count Total HTTP request count grouped by status code.\n# TYPE http_requests_count counter\nhttp_requests_count{status_code=\"2XX\",app=\"juiceshop\"} 2590\nhttp_requests_count{status_code=\"5XX\",app=\"juiceshop\"} 107\nhttp_requests_count{status_code=\"3XX\",app=\"juiceshop\"} 1\nhttp_requests_count{status_code=\"4XX\",app=\"juiceshop\"} 1\n\n# HELP juiceshop_startup_duration_seconds Duration juiceshop required to perform a certain task during startup\n# TYPE juiceshop_startup_duration_seconds gauge\njuiceshop_startup_duration_seconds{task=\"validateConfig\",app=\"juiceshop\"} 0.026059232\njuiceshop_startup_duration_seconds{task=\"cleanupFtpFolder\",app=\"juiceshop\"} 0.106612161\njuiceshop_startup_duration_seconds{task=\"validatePreconditions\",app=\"juiceshop\"} 0.736920475\njuiceshop_startup_duration_seconds{task=\"datacreator\",app=\"juiceshop\"} 6.387883567\njuiceshop_startup_duration_seconds{task=\"customizeApplication\",app=\"juiceshop\"} 0.005662112\njuiceshop_startup_duration_seconds{task=\"customizeEasterEgg\",app=\"juiceshop\"} 0.002790808\njuiceshop_startup_duration_seconds{task=\"ready\",app=\"juiceshop\"} 6.534\n\n# HELP process_cpu_user_seconds_total Total user CPU time spent in seconds.\n# TYPE process_cpu_user_seconds_total counter\nprocess_cpu_user_seconds_total{app=\"juiceshop\"} 26.327383\n\n# HELP process_cpu_system_seconds_total Total system CPU time spent in seconds.\n# TYPE process_cpu_system_seconds_total counter\nprocess_cpu_system_seconds_total{app=\"juiceshop\"} 8.438316\n\n# HELP process_cpu_seconds_total Total user and system CPU time spent in seconds.\n# TYPE process_cpu_seconds_total counter\nprocess_cpu_seconds_total{app=\"juiceshop\"} 34.765699\n\n# HELP process_start_time_seconds Start time of the process since unix epoch in seconds.\n# TYPE process_start_time_seconds gauge\nprocess_start_time_seconds{app=\"juiceshop\"} 1788191723\n\n# HELP process_resident_memory_bytes Resident memory size in bytes.\n# TYPE process_resident_memory_bytes gauge\nprocess_resident_memory_bytes{app=\"juiceshop\"} 1586016256\n\n# HELP process_virtual_memory_bytes Virtual memory size in bytes.\n# TYPE process_virtual_memory_bytes gauge\nprocess_virtual_memory_bytes{app=\"juiceshop\"} 11754446848\n\n# HELP process_heap_bytes Process heap size in bytes.\n# TYPE process_heap_bytes gauge\nprocess_heap_bytes{app=\"juiceshop\"} 2153025536\n\n# HELP process_open_fds Number of open file descriptors.\n# TYPE pr

...[truncated 23702 chars — full evidence in the evidence vault; sha256 above covers the complete artifact]
```
**Artifact SHA-256 Hash**: `2c395806dcc234f24d73c29c5a336a7213b73cebf09f2ccca07fc99f1cfc4b38`
**Chain of Custody ID**: `no-audit-event`

---

### 11. Public Swagger API - Detect
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
[{"type": "nuclei_finding", "template": "swagger-api", "matched_at": "http://127.0.0.1//api-docs/swagger.json", "url": "http://127.0.0.1/", "request": "GET //api-docs/swagger.json HTTP/1.1\r\nHost: 127.0.0.1\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; rv:128.0) Gecko/20100101 Firefox/128.0\r\nAccept: text/html, application/json\r\nAccept-Language: en\r\nAccept-Encoding: gzip\r\n\r\n", "response": "HTTP/1.1 200 OK\r\nConnection: close\r\nTransfer-Encoding: chunked\r\nAccess-Control-Allow-Origin: *\r\nContent-Type: text/html; charset=utf-8\r\nDate: Mon, 31 Aug 2026 15:53:24 GMT\r\nEtag: W/\"c22-H8FH9nKD8DeX/nvIRrte6ZjP2a4\"\r\nFeature-Policy: payment 'self'\r\nVary: Accept-Encoding\r\nX-Content-Type-Options: nosniff\r\nX-Frame-Options: SAMEORIGIN\r\nX-Recruiting: /#/jobs\r\n\r\n\n<!-- HTML for static distribution bundle build -->\n<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n  <meta charset=\"UTF-8\">\n  \n  <title>Swagger UI</title>\n  <link rel=\"stylesheet\" type=\"text/css\" href=\"./swagger-ui.css\" >\n  <link rel=\"icon\" type=\"image/png\" href=\"./favicon-32x32.png\" sizes=\"32x32\" /><link rel=\"icon\" type=\"image/png\" href=\"./favicon-16x16.png\" sizes=\"16x16\" />\n  <style>\n    html\n    {\n      box-sizing: border-box;\n      overflow: -moz-scrollbars-vertical;\n      overflow-y: scroll;\n    }\n    *,\n    *:before,\n    *:after\n    {\n      box-sizing: inherit;\n    }\n\n    body {\n      margin:0;\n      background: #fafafa;\n    }\n  </style>\n</head>\n\n<body>\n\n<svg xmlns=\"http://www.w3.org/2000/svg\" xmlns:xlink=\"http://www.w3.org/1999/xlink\" style=\"position:absolute;width:0;height:0\">\n  <defs>\n    <symbol viewBox=\"0 0 20 20\" id=\"unlocked\">\n      <path d=\"M15.8 8H14V5.6C14 2.703 12.665 1 10 1 7.334 1 6 2.703 6 5.6V6h2v-.801C8 3.754 8.797 3 10 3c1.203 0 2 .754 2 2.199V8H4c-.553 0-1 .646-1 1.199V17c0 .549.428 1.139.951 1.307l1.197.387C5.672 18.861 6.55 19 7.1 19h5.8c.549 0 1.428-.139 1.951-.307l1.196-.387c.524-.167.953-.757.953-1.306V9.199C17 8.646 16.352 8 15.8 8z\"></path>\n    </symbol>\n\n    <symbol viewBox=\"0 0 20 20\" id=\"locked\">\n      <path d=\"M15.8 8H14V5.6C14 2.703 12.665 1 10 1 7.334 1 6 2.703 6 5.6V8H4c-.553 0-1 .646-1 1.199V17c0 .549.428 1.139.951 1.307l1.197.387C5.672 18.861 6.55 19 7.1 19h5.8c.549 0 1.428-.139 1.951-.307l1.196-.387c.524-.167.953-.757.953-1.306V9.199C17 8.646 16.352 8 15.8 8zM12 8H8V5.199C8 3.754 8.797 3 10 3c1.203 0 2 .754 2 2.199V8z\"/>\n    </symbol>\n\n    <symbol viewBox=\"0 0 20 20\" id=\"close\">\n      <path d=\"M14.348 14.849c-.469.469-1.229.469-1.697 0L10 11.819l-2.651 3.029c-.469.469-1.229.469-1.697 0-.469-.469-.469-1.229 0-1.697l2.758-3.15-2.759-3.152c-.469-.469-.469-1.228 0-1.697.469-.469 1.228-.469 1.697 0L10 8.183l2.651-3.031c.469-.469 1.228-.469 1.697 0 .469.469.469 1.229 0 1.697l-2.758 3.152 2.758 3.15c.469.469.469 1.229 0 1.698z\"/>\n    </symbol>\n\n    <symbol viewBox=\"0 0 20 20\" id=\"large-arrow\">\n      <path d=\"M13.25 10L6.109 2.58c-.268-.27-.268-.707 0-.979.268-.27.701-.27.969 0l7.83 7.908c.268.271.268.709 0 .979l-7.83 7.908c-.268.271-.701.27-.969 0-.268-.269-.268-.707 0-.979L13.25 10z\"/>\n    </symbol>\n\n    <symbol viewBox=\"0 0 20 20\" id=\"large-arrow-down\">\n      <path d=\"M17.418 6.109c.272-.268.709-.268.979 0s.271.701 0 .969l-7.908 7.83c-.27.268-.707.268-.979 0l-7.908-7.83c-.27-.268-.27-.701 0-.969.271-.268.709-.268.979 0L10 13.25l7.418-7.141z\"/>\n    </symbol>\n\n\n    <symbol viewBox=\"0 0 24 24\" id=\"jump-to\">\n      <path d=\"M19 7v4H5.83l3.58-3.59L8 6l-6 6 6 6 1.41-1.41L5.83 13H21V7z\"/>\n    </symbol>\n\n    <symbol viewBox=\"0 0 24 24\" id=\"expand\">\n      <path d=\"M10 18h4v-2h-4v2zM3 6v2h18V6H3zm3 7h12v-2H6v2z\"/>\n    </symbol>\n\n  </defs>\n</svg>\n\n<div id=\"swagger-ui\"></div>\n\n<script src=\"./swagger-ui-bundle.js\"> </script>\n<script src=\"./swagger-ui-standalone-preset.js\"> </script>\n<script src=\"./swagger-ui-init.js\"> </script>\n\n\n\n<style>\n  .swagger-ui .topbar .download-url-wrapper { 

...[truncated 87 chars — full evidence in the evidence vault; sha256 above covers the complete artifact]
```
**Artifact SHA-256 Hash**: `fbfbeeeeb4049ba9dc0a8ff80744bb5bdc012e080e3eaa6ec9ef21d2e3f7f3b0`
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
[{"type": "nuclei_finding", "template": "security-txt", "matched_at": "http://127.0.0.1/.well-known/security.txt", "url": "http://127.0.0.1/", "request": "GET /.well-known/security.txt HTTP/1.1\r\nHost: 127.0.0.1\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/79.0.3945.79 Safari/537.36\r\nConnection: close\r\nAccept: */*\r\nAccept-Language: en\r\nAccept-Encoding: gzip\r\n\r\n", "response": "HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: 475\r\nAccess-Control-Allow-Origin: *\r\nContent-Type: text/plain; charset=utf-8\r\nDate: Mon, 31 Aug 2026 15:55:49 GMT\r\nEtag: W/\"1db-BOnKc7IgWp3ijOKOSwppHnIiqhY\"\r\nFeature-Policy: payment 'self'\r\nVary: Accept-Encoding\r\nX-Content-Type-Options: nosniff\r\nX-Frame-Options: SAMEORIGIN\r\nX-Recruiting: /#/jobs\r\n\r\nContact: mailto:donotreply@owasp-juice.shop\nEncryption: https://keybase.io/bkimminich/pgp_keys.asc?fingerprint=19c01cb7157e4645e9e2c863062a85a8cbfbdcda\nAcknowledgements: /#/score-board\nPreferred-languages: en, ar, az, bg, bn, ca, cs, da, de, ga, el, es, et, fi, fr, ka, he, hi, hu, id, it, ja, ko, lv, my, nl, no, pl, pt, ro, ru, si, sv, th, tr, uk, zh\nHiring: /#/jobs\nCsaf: http://localhost:3000/.well-known/csaf/provider-metadata.json\nExpires: Tue, 31 Aug 2027 15:55:26 GMT", "extracted_results": [" mailto:donotreply@owasp-juice.shop"]}]
```
**Artifact SHA-256 Hash**: `3937b9b22b793fdf63e076d985a76a220d8747b3258555bffecde0f2f7d4b05d`
**Chain of Custody ID**: `no-audit-event`

---

### 13. robots.txt endpoint prober
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
[{"type": "nuclei_finding", "template": "robots-txt-endpoint", "matched_at": "http://127.0.0.1/robots.txt", "url": "http://127.0.0.1/", "request": "GET /robots.txt HTTP/1.1\r\nHost: 127.0.0.1\r\nUser-Agent: Mozilla/5.0 (ZZ; Linux i686) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36\r\nConnection: close\r\nAccept: */*\r\nAccept-Language: en\r\nAccept-Encoding: gzip\r\n\r\n", "response": "HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: 28\r\nAccess-Control-Allow-Origin: *\r\nContent-Type: text/plain; charset=utf-8\r\nDate: Mon, 31 Aug 2026 15:55:53 GMT\r\nEtag: W/\"1c-8HgF6mNyhsSFK0pascC9uB0wjX0\"\r\nFeature-Policy: payment 'self'\r\nVary: Accept-Encoding\r\nX-Content-Type-Options: nosniff\r\nX-Frame-Options: SAMEORIGIN\r\nX-Recruiting: /#/jobs\r\n\r\nUser-agent: *\nDisallow: /ftp", "extracted_results": ["/ftp"]}]
```
**Artifact SHA-256 Hash**: `1cf10241216dbc6590dc764c6d4aeb37bbc7c8077894146ea867bfab8fc65e93`
**Chain of Custody ID**: `no-audit-event`

---

### 14. robots.txt file
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
[{"type": "nuclei_finding", "template": "robots-txt", "matched_at": "http://127.0.0.1/robots.txt", "url": "http://127.0.0.1/", "request": "GET /robots.txt HTTP/1.1\r\nHost: 127.0.0.1\r\nUser-Agent: Mozilla/5.0 (Windows NT 6.2; rv:31.0) Gecko/20100101 Firefox/31.0\r\nConnection: close\r\nAccept: */*\r\nAccept-Language: en\r\nAccept-Encoding: gzip\r\n\r\n", "response": "HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: 28\r\nAccess-Control-Allow-Origin: *\r\nContent-Type: text/plain; charset=utf-8\r\nDate: Mon, 31 Aug 2026 15:56:09 GMT\r\nEtag: W/\"1c-8HgF6mNyhsSFK0pascC9uB0wjX0\"\r\nFeature-Policy: payment 'self'\r\nVary: Accept-Encoding\r\nX-Content-Type-Options: nosniff\r\nX-Frame-Options: SAMEORIGIN\r\nX-Recruiting: /#/jobs\r\n\r\nUser-agent: *\nDisallow: /ftp", "extracted_results": null}]
```
**Artifact SHA-256 Hash**: `2c46399bfb3bcf0d82016fdf8f2f5cc1cfadf85ef11a8df322122b2cdc27eddf`
**Chain of Custody ID**: `no-audit-event`

---

### 15. MySQL Info - Enumeration
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

### 16. Redis Info - Detect
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
[{"type": "nuclei_finding", "template": "redis-info", "matched_at": "127.0.0.1:6379", "url": "127.0.0.1:6379", "request": "const redis = require('nuclei/redis');\nconst info = redis.GetServerInfo(Host, Port);\nExport(info);", "response": "# Server\r\nredis_version:7.0.15\r\nredis_git_sha1:00000000\r\nredis_git_dirty:0\r\nredis_build_id:e53ff17674aa6190\r\nredis_mode:standalone\r\nos:Linux 6.6.87.2-microsoft-standard-WSL2 x86_64\r\narch_bits:64\r\nmonotonic_clock:POSIX clock_gettime\r\nmultiplexing_api:epoll\r\natomicvar_api:c11-builtin\r\ngcc_version:13.3.0\r\nprocess_id:183\r\nprocess_supervised:systemd\r\nrun_id:c7b80a33478526d60213ef2ca0a4a997767f1f96\r\ntcp_port:6379\r\nserver_time_usec:1788191737005847\r\nuptime_in_seconds:38679\r\nuptime_in_days:0\r\nhz:10\r\nconfigured_hz:10\r\nlru_clock:9806840\r\nexecutable:/usr/bin/redis-server\r\nconfig_file:/etc/redis/redis.conf\r\nio_threads_active:0\r\n\r\n# Clients\r\nconnected_clients:1\r\ncluster_connections:0\r\nmaxclients:10000\r\nclient_recent_max_input_buffer:0\r\nclient_recent_max_output_buffer:0\r\nblocked_clients:0\r\ntracking_clients:0\r\nclients_in_timeout_table:0\r\n\r\n# Memory\r\nused_memory:1191024\r\nused_memory_human:1.14M\r\nused_memory_rss:13762560\r\nused_memory_rss_human:13.12M\r\nused_memory_peak:1191024\r\nused_memory_peak_human:1.14M\r\nused_memory_peak_perc:100.21%\r\nused_memory_overhead:879576\r\nused_memory_startup:876272\r\nused_memory_dataset:311448\r\nused_memory_dataset_perc:98.95%\r\nallocator_allocated:1670672\r\nallocator_active:1994752\r\nallocator_resident:6787072\r\ntotal_system_memory:8153911296\r\ntotal_system_memory_human:7.59G\r\nused_memory_lua:31744\r\nused_memory_vm_eval:31744\r\nused_memory_lua_human:31.00K\r\nused_memory_scripts_eval:0\r\nnumber_of_cached_scripts:0\r\nnumber_of_functions:0\r\nnumber_of_libraries:0\r\nused_memory_vm_functions:32768\r\nused_memory_vm_total:64512\r\nused_memory_vm_total_human:63.00K\r\nused_memory_functions:200\r\nused_memory_scripts:200\r\nused_memory_scripts_human:200B\r\nmaxmemory:0\r\nmaxmemory_human:0B\r\nmaxmemory_policy:noeviction\r\nallocator_frag_ratio:1.19\r\nallocator_frag_bytes:324080\r\nallocator_rss_ratio:3.40\r\nallocator_rss_bytes:4792320\r\nrss_overhead_ratio:2.03\r\nrss_overhead_bytes:6975488\r\nmem_fragmentation_ratio:12.50\r\nmem_fragmentation_bytes:12661544\r\nmem_not_counted_for_evict:0\r\nmem_replication_backlog:0\r\nmem_total_replication_buffers:0\r\nmem_clients_slaves:0\r\nmem_clients_normal:0\r\nmem_cluster_links:0\r\nmem_aof_buffer:0\r\nmem_allocator:jemalloc-5.3.0\r\nactive_defrag_running:0\r\nlazyfree_pending_objects:0\r\nlazyfreed_objects:0\r\n\r\n# Persistence\r\nloading:0\r\nasync_loading:0\r\ncurrent_cow_peak:0\r\ncurrent_cow_size:0\r\ncurrent_cow_size_age:0\r\ncurrent_fork_perc:0.00\r\ncurrent_save_keys_processed:0\r\ncurrent_save_keys_total:0\r\nrdb_changes_since_last_save:0\r\nrdb_bgsave_in_progress:0\r\nrdb_last_save_time:1788153058\r\nrdb_last_bgsave_status:ok\r\nrdb_last_bgsave_time_sec:-1\r\nrdb_current_bgsave_time_sec:-1\r\nrdb_saves:0\r\nrdb_last_cow_size:0\r\nrdb_last_load_keys_expired:0\r\nrdb_last_load_keys_loaded:64\r\naof_enabled:0\r\naof_rewrite_in_progress:0\r\naof_rewrite_scheduled:0\r\naof_last_rewrite_time_sec:-1\r\naof_current_rewrite_time_sec:-1\r\naof_last_bgrewrite_status:ok\r\naof_rewrites:0\r\naof_rewrites_consecutive_failures:0\r\naof_last_write_status:ok\r\naof_last_cow_size:0\r\nmodule_fork_in_progress:0\r\nmodule_fork_last_cow_size:0\r\n\r\n# Stats\r\ntotal_connections_received:10\r\ntotal_commands_processed:2\r\ninstantaneous_ops_per_sec:0\r\ntotal_net_input_bytes:174\r\ntotal_net_output_bytes:259\r\ntotal_net_repl_input_bytes:0\r\ntotal_net_repl_output_bytes:0\r\ninstantaneous_input_kbps:0.00\r\ninstantaneous_output_kbps:0.00\r\ninstantaneous_input_repl_kbps:0.00\r\ninstantaneous_output_repl_kbps:0.00\r\nrejected_connections:0\r\nsync_full:0\r\nsync_partial_ok:0\r\nsync_partial_err:0\r\nexpired_keys:0\r\nexpired_stale_perc:0.00\r\nexpired_

...[truncated 2130 chars — full evidence in the evidence vault; sha256 above covers the complete artifact]
```
**Artifact SHA-256 Hash**: `a1a73cb3dfd71c5b71a62a92f3bf59bb8ed10e440a385b936d5a96da19086c36`
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
[{"type": "nuclei_finding", "template": "smb-enum", "matched_at": "127.0.0.1:445", "url": "127.0.0.1:445", "request": "var m = require(\"nuclei/smb\");\nvar c = m.SMBClient();\nvar response = c.ListSMBv2Metadata(Host, Port);\nExport(response);", "response": "{\n  \"SigningEnabled\": true,\n  \"SigningRequired\": true,\n  \"OSVersion\": \"10.0.26100\",\n  \"NetBIOSComputerName\": \"DESKTOP-VJ5O45D\",\n  \"NetBIOSDomainName\": \"DESKTOP-VJ5O45D\",\n  \"DNSComputerName\": \"DESKTOP-VJ5O45D\",\n  \"DNSDomainName\": \"DESKTOP-VJ5O45D\",\n  \"ForestName\": \"\"\n}", "extracted_results": ["ForestName: ", "OSVersion: 10.0.26100", "NetBIOSComputerName: DESKTOP-VJ5O45D", "NetBIOSDomainName: DESKTOP-VJ5O45D", "DNSComputerNamen: DESKTOP-VJ5O45D", "DNSComputerName: DESKTOP-VJ5O45D"], "false_positive_signal": {"out_of_scan_scope": true, "matched_endpoint": "127.0.0.1:445", "scoped_endpoints": ["127.0.0.1:80"], "reason": "nuclei matched a service on a host port this scan was not pointed at (shared-host service misattribution \u2014 real service, wrong engagement)"}}]
```
**Artifact SHA-256 Hash**: `20c6d559295a9c69e94d4075118934ddf95bf0fd2be5e32455bef82ba75400ea`
**Chain of Custody ID**: `no-audit-event`

---

### 19. SMB Version - Detection
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
[{"type": "nuclei_finding", "template": "smb-version-detect", "matched_at": "127.0.0.1:445", "url": "127.0.0.1:445", "request": "let m = require(\"nuclei/smb\");\nlet c = new m.SMBClient();\nlet response = c.ConnectSMBInfoMode(Host, Port);\nExport(response);", "response": "{\n  \"SupportV1\": false,\n  \"Version\": {\n    \"Major\": 2,\n    \"Minor\": 1,\n    \"Revision\": 0,\n    \"VerString\": \"SMB 2.1\"\n  },\n  \"NativeOs\": \"\",\n  \"NTLM\": \"\",\n  \"GroupName\": \"\",\n  \"Capabilities\": {\n    \"DFSSupport\": true,\n    \"Leasing\": true,\n    \"LargeMTU\": true,\n    \"MultiChan\": false,\n    \"Persist\": false,\n    \"DirLeasing\": false,\n    \"Encryption\": false\n  },\n  \"HasNTLM\": true,\n  \"NegotiationLog\": {\n    \"HeaderLog\": {\n      \"ProtocolID\": [\n        0,\n        0,\n        0,\n        0,\n        254,\n        83,\n        77,\n        66\n      ],\n      \"Status\": 0,\n      \"Command\": 0,\n      \"Credits\": 1,\n      \"Flags\": 1\n    },\n    \"ProtocolID\": [\n      0,\n      0,\n      0,\n      0,\n      254,\n      83,\n      77,\n      66\n    ],\n    \"Status\": 0,\n    \"Command\": 0,\n    \"Credits\": 1,\n    \"Flags\": 1,\n    \"SecurityMode\": 3,\n    \"DialectRevision\": 528,\n    \"ServerGuid\": [\n      0,\n      0,\n      0,\n      0,\n      0,\n      0,\n      0,\n      0,\n      0,\n      0,\n      0,\n      0,\n      0,\n      0,\n      0,\n      0,\n      244,\n      117,\n      7,\n      244,\n      85,\n      143,\n      174,\n      70,\n      151,\n      62,\n      59,\n      42,\n      30,\n      59,\n      134,\n      201\n    ],\n    \"Capabilities\": 7,\n    \"SystemTime\": 1788191737,\n    \"ServerStartTime\": 1240428288,\n    \"AuthenticationTypes\": [\n      \"1.3.6.1.4.1.311.2.2.30\",\n      \"1.3.6.1.4.1.311.2.2.10\"\n    ]\n  },\n  \"SessionSetupLog\": {\n    \"HeaderLog\": {\n      \"ProtocolID\": [\n        0,\n        0,\n        0,\n        0,\n        254,\n        83,\n        77,\n        66\n      ],\n      \"Status\": 3221225494,\n      \"Command\": 1,\n      \"Credits\": 1,\n      \"Flags\": 1\n    },\n    \"ProtocolID\": [\n      0,\n      0,\n      0,\n      0,\n      254,\n      83,\n      77,\n      66\n    ],\n    \"Status\": 3221225494,\n    \"Command\": 1,\n    \"Credits\": 1,\n    \"Flags\": 1,\n    \"SetupFlags\": 0,\n    \"TargetName\": \"DESKTOP-VJ5O45D\",\n    \"NegotiateFlags\": 2726953477\n  }\n}", "extracted_results": ["SMB 2.1"], "false_positive_signal": {"out_of_scan_scope": true, "matched_endpoint": "127.0.0.1:445", "scoped_endpoints": ["127.0.0.1:80"], "reason": "nuclei matched a service on a host port this scan was not pointed at (shared-host service misattribution \u2014 real service, wrong engagement)"}}]
```
**Artifact SHA-256 Hash**: `03d56cd0dedc3e2e7125a12170b584f178c8bf07741e265cda85001134625d40`
**Chain of Custody ID**: `no-audit-event`

---

### 20. SMB Operating System - Detect
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

### 21. SMB2 Server Time - Detection
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
[{"type": "nuclei_finding", "template": "smb2-server-time", "matched_at": "127.0.0.1:445", "url": "127.0.0.1:445", "request": "var m = require(\"nuclei/smb\");\nvar c = m.SMBClient();\nvar response = c.ConnectSMBInfoMode(Host, Port);\nvar systemTime = new Date(response.NegotiationLog.SystemTime * 1000).toISOString();\nvar serverstartTime = new Date(response.NegotiationLog.ServerStartTime * 1000).toISOString();\nvar result = \"SystemTime: \" + systemTime + \" ServerStartTime: \" + serverstartTime;\nresult", "response": "SystemTime: 2026-08-31T15:55:37.000Z ServerStartTime: 2009-04-22T19:24:48.000Z", "extracted_results": ["SystemTime: 2026-08-31T15:55:37.000Z ServerStartTime: 2009-04-22T19:24:48.000Z"], "false_positive_signal": {"out_of_scan_scope": true, "matched_endpoint": "127.0.0.1:445", "scoped_endpoints": ["127.0.0.1:80"], "reason": "nuclei matched a service on a host port this scan was not pointed at (shared-host service misattribution \u2014 real service, wrong engagement)"}}]
```
**Artifact SHA-256 Hash**: `561efa4175af74047991cdb8a6c3b456b126ed4e2485d75cd15a6bc8d1481faa`
**Chain of Custody ID**: `no-audit-event`

---

### 22. smb2-capabilities - Enumeration
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
[{"type": "nuclei_finding", "template": "smb2-capabilities", "matched_at": "127.0.0.1:445", "url": "127.0.0.1:445", "request": "var m = require(\"nuclei/smb\");\nvar c = m.SMBClient();\nvar response = c.ConnectSMBInfoMode(Host, Port);\nExport(response);", "response": "{\n  \"SupportV1\": false,\n  \"Version\": {\n    \"Major\": 2,\n    \"Minor\": 1,\n    \"Revision\": 0,\n    \"VerString\": \"SMB 2.1\"\n  },\n  \"NativeOs\": \"\",\n  \"NTLM\": \"\",\n  \"GroupName\": \"\",\n  \"Capabilities\": {\n    \"DFSSupport\": true,\n    \"Leasing\": true,\n    \"LargeMTU\": true,\n    \"MultiChan\": false,\n    \"Persist\": false,\n    \"DirLeasing\": false,\n    \"Encryption\": false\n  },\n  \"HasNTLM\": true,\n  \"NegotiationLog\": {\n    \"HeaderLog\": {\n      \"ProtocolID\": [\n        0,\n        0,\n        0,\n        0,\n        254,\n        83,\n        77,\n        66\n      ],\n      \"Status\": 0,\n      \"Command\": 0,\n      \"Credits\": 1,\n      \"Flags\": 1\n    },\n    \"ProtocolID\": [\n      0,\n      0,\n      0,\n      0,\n      254,\n      83,\n      77,\n      66\n    ],\n    \"Status\": 0,\n    \"Command\": 0,\n    \"Credits\": 1,\n    \"Flags\": 1,\n    \"SecurityMode\": 3,\n    \"DialectRevision\": 528,\n    \"ServerGuid\": [\n      0,\n      0,\n      0,\n      0,\n      0,\n      0,\n      0,\n      0,\n      0,\n      0,\n      0,\n      0,\n      0,\n      0,\n      0,\n      0,\n      244,\n      117,\n      7,\n      244,\n      85,\n      143,\n      174,\n      70,\n      151,\n      62,\n      59,\n      42,\n      30,\n      59,\n      134,\n      201\n    ],\n    \"Capabilities\": 7,\n    \"SystemTime\": 1788191737,\n    \"ServerStartTime\": 1240428288,\n    \"AuthenticationTypes\": [\n      \"1.3.6.1.4.1.311.2.2.30\",\n      \"1.3.6.1.4.1.311.2.2.10\"\n    ]\n  },\n  \"SessionSetupLog\": {\n    \"HeaderLog\": {\n      \"ProtocolID\": [\n        0,\n        0,\n        0,\n        0,\n        254,\n        83,\n        77,\n        66\n      ],\n      \"Status\": 3221225494,\n      \"Command\": 1,\n      \"Credits\": 1,\n      \"Flags\": 1\n    },\n    \"ProtocolID\": [\n      0,\n      0,\n      0,\n      0,\n      254,\n      83,\n      77,\n      66\n    ],\n    \"Status\": 3221225494,\n    \"Command\": 1,\n    \"Credits\": 1,\n    \"Flags\": 1,\n    \"SetupFlags\": 0,\n    \"TargetName\": \"DESKTOP-VJ5O45D\",\n    \"NegotiateFlags\": 2726953477\n  }\n}", "extracted_results": ["[\"DFSSupport\",\"LargeMTU\",\"Leasing\"]"], "false_positive_signal": {"out_of_scan_scope": true, "matched_endpoint": "127.0.0.1:445", "scoped_endpoints": ["127.0.0.1:80"], "reason": "nuclei matched a service on a host port this scan was not pointed at (shared-host service misattribution \u2014 real service, wrong engagement)"}}]
```
**Artifact SHA-256 Hash**: `f0a8aae60b7c473d8cef54b60bd2fbb4ddf09d0c67fdc4637c14f11ea3e4fec2`
**Chain of Custody ID**: `no-audit-event`

---

### 23. PostgreSQL Authentication - Detect
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
[{"type": "nuclei_finding", "template": "http-missing-security-headers", "matched_at": "http://127.0.0.1/", "url": "http://127.0.0.1/", "request": "GET / HTTP/1.1\r\nHost: 127.0.0.1\r\nUser-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 14_0) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Safari/605.1.15\r\nConnection: close\r\nAccept: */*\r\nAccept-Language: en\r\nAccept-Encoding: gzip\r\n\r\n", "response": "HTTP/1.1 200 OK\r\nConnection: close\r\nTransfer-Encoding: chunked\r\nAccept-Ranges: bytes\r\nAccess-Control-Allow-Origin: *\r\nCache-Control: public, max-age=0\r\nContent-Type: text/html; charset=UTF-8\r\nDate: Mon, 31 Aug 2026 15:55:46 GMT\r\nEtag: W/\"26af-1a058887300\"\r\nFeature-Policy: payment 'self'\r\nLast-Modified: Mon, 31 Aug 2026 15:55:32 GMT\r\nVary: Accept-Encoding\r\nX-Content-Type-Options: nosniff\r\nX-Frame-Options: SAMEORIGIN\r\nX-Recruiting: /#/jobs\r\n\r\n<!--\n  ~ Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.\n  ~ SPDX-License-Identifier: MIT\n  -->\n\n<!doctype html>\n<html lang=\"en\" data-beasties-container>\n<head>\n  <meta charset=\"utf-8\">\n  <title>OWASP Juice Shop</title>\n  <meta name=\"description\" content=\"Probably the most modern and sophisticated insecure web application\">\n  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n  <link rel=\"preconnect\" href=\"https://fonts.googleapis.com\">\n  <link rel=\"preconnect\" href=\"https://fonts.gstatic.com\" crossorigin>\n  <style>@font-face{font-family:'VT323';font-style:normal;font-weight:400;font-display:swap;src:url(https://fonts.gstatic.com/s/vt323/v18/pxiKyp0ihIEF2isQFJXGdg.woff2) format('woff2');unicode-range:U+0102-0103, U+0110-0111, U+0128-0129, U+0168-0169, U+01A0-01A1, U+01AF-01B0, U+0300-0301, U+0303-0304, U+0308-0309, U+0323, U+0329, U+1EA0-1EF9, U+20AB;}@font-face{font-family:'VT323';font-style:normal;font-weight:400;font-display:swap;src:url(https://fonts.gstatic.com/s/vt323/v18/pxiKyp0ihIEF2isRFJXGdg.woff2) format('woff2');unicode-range:U+0100-02BA, U+02BD-02C5, U+02C7-02CC, U+02CE-02D7, U+02DD-02FF, U+0304, U+0308, U+0329, U+1D00-1DBF, U+1E00-1E9F, U+1EF2-1EFF, U+2020, U+20A0-20AB, U+20AD-20C0, U+2113, U+2C60-2C7F, U+A720-A7FF;}@font-face{font-family:'VT323';font-style:normal;font-weight:400;font-display:swap;src:url(https://fonts.gstatic.com/s/vt323/v18/pxiKyp0ihIEF2isfFJU.woff2) format('woff2');unicode-range:U+0000-00FF, U+0131, U+0152-0153, U+02BB-02BC, U+02C6, U+02DA, U+02DC, U+0304, U+0308, U+0329, U+2000-206F, U+20AC, U+2122, U+2191, U+2193, U+2212, U+2215, U+FEFF, U+FFFD;}</style>\n  <link id=\"favicon\" rel=\"icon\" type=\"image/x-icon\" href=\"assets/public/favicon_js.ico\">\n  <script>\n    window.addEventListener(\"load\", function(){\n      window.cookieconsent.initialise({\n        \"palette\": {\n          \"popup\": { \"background\": \"var(--theme-primary)\", \"text\": \"var(--theme-text)\" },\n          \"button\": { \"background\": \"var(--theme-accent)\", \"text\": \"var(--theme-text)\" }\n        },\n        \"theme\": \"classic\",\n        \"position\": \"bottom-right\",\n        \"content\": { \"message\": \"This website uses fruit cookies to ensure you get the juiciest tracking experience.\", \"dismiss\": \"Me want it!\", \"link\": \"But me wait!\", \"href\": \"https://www.youtube.com/watch?v=9PnbKL3wuH4\" }\n      })});\n  </script>\n<style>.bluegrey-lightgreen-theme{--mat-sys-background:#121316;--mat-sys-error:#ffb4ab;--mat-sys-error-container:#93000a;--mat-sys-inverse-on-surface:#2f3033;--mat-sys-inverse-primary:#005cbb;--mat-sys-inverse-surface:#e3e2e6;--mat-sys-on-background:#e3e2e6;--mat-sys-on-error:#690005;--mat-sys-on-error-container:#ffdad6;--mat-sys-on-primary:#002f65;--mat-sys-on-primary-container:#d7e3ff;--mat-sys-on-primary-fixed:#001b3f;--mat-sys-on-primary-fixed-variant:#00458f;--mat-sys-on-secondary:#283041;--mat-sys-on-secondary-container:#dae2f9;--mat-sys-on-secondary-fixed:#131c2b;--mat-sys-on-secondary-fixed-variant:#3e475

...[truncated 7175 chars — full evidence in the evidence vault; sha256 above covers the complete artifact]
```
**Artifact SHA-256 Hash**: `a038765bacc193846fb356704a4b727fb302ed5e314cd9682081fc276933f206`
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
[{"type": "nuclei_finding", "template": "x-recruiting-header", "matched_at": "http://127.0.0.1/", "url": "http://127.0.0.1/", "request": "GET / HTTP/1.1\r\nHost: 127.0.0.1\r\nUser-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 13_4) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/13.1 Safari/605.1.15\r\nConnection: close\r\nAccept: */*\r\nAccept-Language: en\r\nAccept-Encoding: gzip\r\n\r\n", "response": "HTTP/1.1 200 OK\r\nConnection: close\r\nTransfer-Encoding: chunked\r\nAccept-Ranges: bytes\r\nAccess-Control-Allow-Origin: *\r\nCache-Control: public, max-age=0\r\nContent-Type: text/html; charset=UTF-8\r\nDate: Mon, 31 Aug 2026 15:56:02 GMT\r\nEtag: W/\"26af-1a058887300\"\r\nFeature-Policy: payment 'self'\r\nLast-Modified: Mon, 31 Aug 2026 15:55:32 GMT\r\nVary: Accept-Encoding\r\nX-Content-Type-Options: nosniff\r\nX-Frame-Options: SAMEORIGIN\r\nX-Recruiting: /#/jobs\r\n\r\n<!--\n  ~ Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.\n  ~ SPDX-License-Identifier: MIT\n  -->\n\n<!doctype html>\n<html lang=\"en\" data-beasties-container>\n<head>\n  <meta charset=\"utf-8\">\n  <title>OWASP Juice Shop</title>\n  <meta name=\"description\" content=\"Probably the most modern and sophisticated insecure web application\">\n  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n  <link rel=\"preconnect\" href=\"https://fonts.googleapis.com\">\n  <link rel=\"preconnect\" href=\"https://fonts.gstatic.com\" crossorigin>\n  <style>@font-face{font-family:'VT323';font-style:normal;font-weight:400;font-display:swap;src:url(https://fonts.gstatic.com/s/vt323/v18/pxiKyp0ihIEF2isQFJXGdg.woff2) format('woff2');unicode-range:U+0102-0103, U+0110-0111, U+0128-0129, U+0168-0169, U+01A0-01A1, U+01AF-01B0, U+0300-0301, U+0303-0304, U+0308-0309, U+0323, U+0329, U+1EA0-1EF9, U+20AB;}@font-face{font-family:'VT323';font-style:normal;font-weight:400;font-display:swap;src:url(https://fonts.gstatic.com/s/vt323/v18/pxiKyp0ihIEF2isRFJXGdg.woff2) format('woff2');unicode-range:U+0100-02BA, U+02BD-02C5, U+02C7-02CC, U+02CE-02D7, U+02DD-02FF, U+0304, U+0308, U+0329, U+1D00-1DBF, U+1E00-1E9F, U+1EF2-1EFF, U+2020, U+20A0-20AB, U+20AD-20C0, U+2113, U+2C60-2C7F, U+A720-A7FF;}@font-face{font-family:'VT323';font-style:normal;font-weight:400;font-display:swap;src:url(https://fonts.gstatic.com/s/vt323/v18/pxiKyp0ihIEF2isfFJU.woff2) format('woff2');unicode-range:U+0000-00FF, U+0131, U+0152-0153, U+02BB-02BC, U+02C6, U+02DA, U+02DC, U+0304, U+0308, U+0329, U+2000-206F, U+20AC, U+2122, U+2191, U+2193, U+2212, U+2215, U+FEFF, U+FFFD;}</style>\n  <link id=\"favicon\" rel=\"icon\" type=\"image/x-icon\" href=\"assets/public/favicon_js.ico\">\n  <script>\n    window.addEventListener(\"load\", function(){\n      window.cookieconsent.initialise({\n        \"palette\": {\n          \"popup\": { \"background\": \"var(--theme-primary)\", \"text\": \"var(--theme-text)\" },\n          \"button\": { \"background\": \"var(--theme-accent)\", \"text\": \"var(--theme-text)\" }\n        },\n        \"theme\": \"classic\",\n        \"position\": \"bottom-right\",\n        \"content\": { \"message\": \"This website uses fruit cookies to ensure you get the juiciest tracking experience.\", \"dismiss\": \"Me want it!\", \"link\": \"But me wait!\", \"href\": \"https://www.youtube.com/watch?v=9PnbKL3wuH4\" }\n      })});\n  </script>\n<style>.bluegrey-lightgreen-theme{--mat-sys-background:#121316;--mat-sys-error:#ffb4ab;--mat-sys-error-container:#93000a;--mat-sys-inverse-on-surface:#2f3033;--mat-sys-inverse-primary:#005cbb;--mat-sys-inverse-surface:#e3e2e6;--mat-sys-on-background:#e3e2e6;--mat-sys-on-error:#690005;--mat-sys-on-error-container:#ffdad6;--mat-sys-on-primary:#002f65;--mat-sys-on-primary-container:#d7e3ff;--mat-sys-on-primary-fixed:#001b3f;--mat-sys-on-primary-fixed-variant:#00458f;--mat-sys-on-secondary:#283041;--mat-sys-on-secondary-container:#dae2f9;--mat-sys-on-secondary-fixed:#131c2b;--mat-sys-on-secondary-fixed-variant:#3e4759;--mat-sy

...[truncated 7172 chars — full evidence in the evidence vault; sha256 above covers the complete artifact]
```
**Artifact SHA-256 Hash**: `4564cfd0372458429f0bcd5a57d6b24fa45ce34f08ab5e1fb575ba0b2d7c8f64`
**Chain of Custody ID**: `no-audit-event`

---

### 26. FingerprintHub Technology Fingerprint
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
[{"type": "nuclei_finding", "template": "fingerprinthub-web-fingerprints", "matched_at": "http://127.0.0.1/", "url": "http://127.0.0.1/", "request": "GET / HTTP/1.1\r\nHost: 127.0.0.1\r\nUser-Agent: Mozilla/5.0 (Debian; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36\r\nConnection: close\r\nAccept: */*\r\nAccept-Language: en\r\nAccept-Encoding: gzip\r\n\r\n", "response": "HTTP/1.1 200 OK\r\nConnection: close\r\nTransfer-Encoding: chunked\r\nAccept-Ranges: bytes\r\nAccess-Control-Allow-Origin: *\r\nCache-Control: public, max-age=0\r\nContent-Type: text/html; charset=UTF-8\r\nDate: Mon, 31 Aug 2026 15:56:05 GMT\r\nEtag: W/\"26af-1a058887300\"\r\nFeature-Policy: payment 'self'\r\nLast-Modified: Mon, 31 Aug 2026 15:55:32 GMT\r\nVary: Accept-Encoding\r\nX-Content-Type-Options: nosniff\r\nX-Frame-Options: SAMEORIGIN\r\nX-Recruiting: /#/jobs\r\n\r\n<!--\n  ~ Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.\n  ~ SPDX-License-Identifier: MIT\n  -->\n\n<!doctype html>\n<html lang=\"en\" data-beasties-container>\n<head>\n  <meta charset=\"utf-8\">\n  <title>OWASP Juice Shop</title>\n  <meta name=\"description\" content=\"Probably the most modern and sophisticated insecure web application\">\n  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n  <link rel=\"preconnect\" href=\"https://fonts.googleapis.com\">\n  <link rel=\"preconnect\" href=\"https://fonts.gstatic.com\" crossorigin>\n  <style>@font-face{font-family:'VT323';font-style:normal;font-weight:400;font-display:swap;src:url(https://fonts.gstatic.com/s/vt323/v18/pxiKyp0ihIEF2isQFJXGdg.woff2) format('woff2');unicode-range:U+0102-0103, U+0110-0111, U+0128-0129, U+0168-0169, U+01A0-01A1, U+01AF-01B0, U+0300-0301, U+0303-0304, U+0308-0309, U+0323, U+0329, U+1EA0-1EF9, U+20AB;}@font-face{font-family:'VT323';font-style:normal;font-weight:400;font-display:swap;src:url(https://fonts.gstatic.com/s/vt323/v18/pxiKyp0ihIEF2isRFJXGdg.woff2) format('woff2');unicode-range:U+0100-02BA, U+02BD-02C5, U+02C7-02CC, U+02CE-02D7, U+02DD-02FF, U+0304, U+0308, U+0329, U+1D00-1DBF, U+1E00-1E9F, U+1EF2-1EFF, U+2020, U+20A0-20AB, U+20AD-20C0, U+2113, U+2C60-2C7F, U+A720-A7FF;}@font-face{font-family:'VT323';font-style:normal;font-weight:400;font-display:swap;src:url(https://fonts.gstatic.com/s/vt323/v18/pxiKyp0ihIEF2isfFJU.woff2) format('woff2');unicode-range:U+0000-00FF, U+0131, U+0152-0153, U+02BB-02BC, U+02C6, U+02DA, U+02DC, U+0304, U+0308, U+0329, U+2000-206F, U+20AC, U+2122, U+2191, U+2193, U+2212, U+2215, U+FEFF, U+FFFD;}</style>\n  <link id=\"favicon\" rel=\"icon\" type=\"image/x-icon\" href=\"assets/public/favicon_js.ico\">\n  <script>\n    window.addEventListener(\"load\", function(){\n      window.cookieconsent.initialise({\n        \"palette\": {\n          \"popup\": { \"background\": \"var(--theme-primary)\", \"text\": \"var(--theme-text)\" },\n          \"button\": { \"background\": \"var(--theme-accent)\", \"text\": \"var(--theme-text)\" }\n        },\n        \"theme\": \"classic\",\n        \"position\": \"bottom-right\",\n        \"content\": { \"message\": \"This website uses fruit cookies to ensure you get the juiciest tracking experience.\", \"dismiss\": \"Me want it!\", \"link\": \"But me wait!\", \"href\": \"https://www.youtube.com/watch?v=9PnbKL3wuH4\" }\n      })});\n  </script>\n<style>.bluegrey-lightgreen-theme{--mat-sys-background:#121316;--mat-sys-error:#ffb4ab;--mat-sys-error-container:#93000a;--mat-sys-inverse-on-surface:#2f3033;--mat-sys-inverse-primary:#005cbb;--mat-sys-inverse-surface:#e3e2e6;--mat-sys-on-background:#e3e2e6;--mat-sys-on-error:#690005;--mat-sys-on-error-container:#ffdad6;--mat-sys-on-primary:#002f65;--mat-sys-on-primary-container:#d7e3ff;--mat-sys-on-primary-fixed:#001b3f;--mat-sys-on-primary-fixed-variant:#00458f;--mat-sys-on-secondary:#283041;--mat-sys-on-secondary-container:#dae2f9;--mat-sys-on-secondary-fixed:#131c2b;--mat-sys-on-secondary-fixed-variant:#3e4759;--mat-

...[truncated 7167 chars — full evidence in the evidence vault; sha256 above covers the complete artifact]
```
**Artifact SHA-256 Hash**: `5970441acd4b185faadff15fa62549234e8cdea95c38ea61828604be8b44da22`
**Chain of Custody ID**: `no-audit-event`

---

### 27. Wappalyzer Technology Detection
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
[{"type": "nuclei_finding", "template": "tech-detect", "matched_at": "http://127.0.0.1/", "url": "http://127.0.0.1/", "request": "GET / HTTP/1.1\r\nHost: 127.0.0.1\r\nUser-Agent: Mozilla/5.0 (Debian; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36\r\nConnection: close\r\nAccept: */*\r\nAccept-Language: en\r\nAccept-Encoding: gzip\r\n\r\n", "response": "HTTP/1.1 200 OK\r\nConnection: close\r\nTransfer-Encoding: chunked\r\nAccept-Ranges: bytes\r\nAccess-Control-Allow-Origin: *\r\nCache-Control: public, max-age=0\r\nContent-Type: text/html; charset=UTF-8\r\nDate: Mon, 31 Aug 2026 15:56:05 GMT\r\nEtag: W/\"26af-1a058887300\"\r\nFeature-Policy: payment 'self'\r\nLast-Modified: Mon, 31 Aug 2026 15:55:32 GMT\r\nVary: Accept-Encoding\r\nX-Content-Type-Options: nosniff\r\nX-Frame-Options: SAMEORIGIN\r\nX-Recruiting: /#/jobs\r\n\r\n<!--\n  ~ Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.\n  ~ SPDX-License-Identifier: MIT\n  -->\n\n<!doctype html>\n<html lang=\"en\" data-beasties-container>\n<head>\n  <meta charset=\"utf-8\">\n  <title>OWASP Juice Shop</title>\n  <meta name=\"description\" content=\"Probably the most modern and sophisticated insecure web application\">\n  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n  <link rel=\"preconnect\" href=\"https://fonts.googleapis.com\">\n  <link rel=\"preconnect\" href=\"https://fonts.gstatic.com\" crossorigin>\n  <style>@font-face{font-family:'VT323';font-style:normal;font-weight:400;font-display:swap;src:url(https://fonts.gstatic.com/s/vt323/v18/pxiKyp0ihIEF2isQFJXGdg.woff2) format('woff2');unicode-range:U+0102-0103, U+0110-0111, U+0128-0129, U+0168-0169, U+01A0-01A1, U+01AF-01B0, U+0300-0301, U+0303-0304, U+0308-0309, U+0323, U+0329, U+1EA0-1EF9, U+20AB;}@font-face{font-family:'VT323';font-style:normal;font-weight:400;font-display:swap;src:url(https://fonts.gstatic.com/s/vt323/v18/pxiKyp0ihIEF2isRFJXGdg.woff2) format('woff2');unicode-range:U+0100-02BA, U+02BD-02C5, U+02C7-02CC, U+02CE-02D7, U+02DD-02FF, U+0304, U+0308, U+0329, U+1D00-1DBF, U+1E00-1E9F, U+1EF2-1EFF, U+2020, U+20A0-20AB, U+20AD-20C0, U+2113, U+2C60-2C7F, U+A720-A7FF;}@font-face{font-family:'VT323';font-style:normal;font-weight:400;font-display:swap;src:url(https://fonts.gstatic.com/s/vt323/v18/pxiKyp0ihIEF2isfFJU.woff2) format('woff2');unicode-range:U+0000-00FF, U+0131, U+0152-0153, U+02BB-02BC, U+02C6, U+02DA, U+02DC, U+0304, U+0308, U+0329, U+2000-206F, U+20AC, U+2122, U+2191, U+2193, U+2212, U+2215, U+FEFF, U+FFFD;}</style>\n  <link id=\"favicon\" rel=\"icon\" type=\"image/x-icon\" href=\"assets/public/favicon_js.ico\">\n  <script>\n    window.addEventListener(\"load\", function(){\n      window.cookieconsent.initialise({\n        \"palette\": {\n          \"popup\": { \"background\": \"var(--theme-primary)\", \"text\": \"var(--theme-text)\" },\n          \"button\": { \"background\": \"var(--theme-accent)\", \"text\": \"var(--theme-text)\" }\n        },\n        \"theme\": \"classic\",\n        \"position\": \"bottom-right\",\n        \"content\": { \"message\": \"This website uses fruit cookies to ensure you get the juiciest tracking experience.\", \"dismiss\": \"Me want it!\", \"link\": \"But me wait!\", \"href\": \"https://www.youtube.com/watch?v=9PnbKL3wuH4\" }\n      })});\n  </script>\n<style>.bluegrey-lightgreen-theme{--mat-sys-background:#121316;--mat-sys-error:#ffb4ab;--mat-sys-error-container:#93000a;--mat-sys-inverse-on-surface:#2f3033;--mat-sys-inverse-primary:#005cbb;--mat-sys-inverse-surface:#e3e2e6;--mat-sys-on-background:#e3e2e6;--mat-sys-on-error:#690005;--mat-sys-on-error-container:#ffdad6;--mat-sys-on-primary:#002f65;--mat-sys-on-primary-container:#d7e3ff;--mat-sys-on-primary-fixed:#001b3f;--mat-sys-on-primary-fixed-variant:#00458f;--mat-sys-on-secondary:#283041;--mat-sys-on-secondary-container:#dae2f9;--mat-sys-on-secondary-fixed:#131c2b;--mat-sys-on-secondary-fixed-variant:#3e4759;--mat-sys-on-surface:#e3e2

...[truncated 7197 chars — full evidence in the evidence vault; sha256 above covers the complete artifact]
```
**Artifact SHA-256 Hash**: `9306a994a27d3ab8f7b6092dfb0701e1faf83d9ce5fe103c2bcd7be1a13e5abb`
**Chain of Custody ID**: `no-audit-event`

---

### 28. Add DOM EventListener - Detection
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
[{"type": "nuclei_finding", "template": "addeventlistener-detect", "matched_at": "http://127.0.0.1/", "url": "http://127.0.0.1/", "request": "GET / HTTP/1.1\r\nHost: 127.0.0.1\r\nUser-Agent: Mozilla/5.0 (CentOS; Linux i686) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36\r\nConnection: close\r\nAccept: */*\r\nAccept-Language: en\r\nAccept-Encoding: gzip\r\n\r\n", "response": "HTTP/1.1 200 OK\r\nConnection: close\r\nTransfer-Encoding: chunked\r\nAccept-Ranges: bytes\r\nAccess-Control-Allow-Origin: *\r\nCache-Control: public, max-age=0\r\nContent-Type: text/html; charset=UTF-8\r\nDate: Mon, 31 Aug 2026 15:56:19 GMT\r\nEtag: W/\"26af-1a058887300\"\r\nFeature-Policy: payment 'self'\r\nLast-Modified: Mon, 31 Aug 2026 15:55:32 GMT\r\nVary: Accept-Encoding\r\nX-Content-Type-Options: nosniff\r\nX-Frame-Options: SAMEORIGIN\r\nX-Recruiting: /#/jobs\r\n\r\n<!--\n  ~ Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.\n  ~ SPDX-License-Identifier: MIT\n  -->\n\n<!doctype html>\n<html lang=\"en\" data-beasties-container>\n<head>\n  <meta charset=\"utf-8\">\n  <title>OWASP Juice Shop</title>\n  <meta name=\"description\" content=\"Probably the most modern and sophisticated insecure web application\">\n  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n  <link rel=\"preconnect\" href=\"https://fonts.googleapis.com\">\n  <link rel=\"preconnect\" href=\"https://fonts.gstatic.com\" crossorigin>\n  <style>@font-face{font-family:'VT323';font-style:normal;font-weight:400;font-display:swap;src:url(https://fonts.gstatic.com/s/vt323/v18/pxiKyp0ihIEF2isQFJXGdg.woff2) format('woff2');unicode-range:U+0102-0103, U+0110-0111, U+0128-0129, U+0168-0169, U+01A0-01A1, U+01AF-01B0, U+0300-0301, U+0303-0304, U+0308-0309, U+0323, U+0329, U+1EA0-1EF9, U+20AB;}@font-face{font-family:'VT323';font-style:normal;font-weight:400;font-display:swap;src:url(https://fonts.gstatic.com/s/vt323/v18/pxiKyp0ihIEF2isRFJXGdg.woff2) format('woff2');unicode-range:U+0100-02BA, U+02BD-02C5, U+02C7-02CC, U+02CE-02D7, U+02DD-02FF, U+0304, U+0308, U+0329, U+1D00-1DBF, U+1E00-1E9F, U+1EF2-1EFF, U+2020, U+20A0-20AB, U+20AD-20C0, U+2113, U+2C60-2C7F, U+A720-A7FF;}@font-face{font-family:'VT323';font-style:normal;font-weight:400;font-display:swap;src:url(https://fonts.gstatic.com/s/vt323/v18/pxiKyp0ihIEF2isfFJU.woff2) format('woff2');unicode-range:U+0000-00FF, U+0131, U+0152-0153, U+02BB-02BC, U+02C6, U+02DA, U+02DC, U+0304, U+0308, U+0329, U+2000-206F, U+20AC, U+2122, U+2191, U+2193, U+2212, U+2215, U+FEFF, U+FFFD;}</style>\n  <link id=\"favicon\" rel=\"icon\" type=\"image/x-icon\" href=\"assets/public/favicon_js.ico\">\n  <script>\n    window.addEventListener(\"load\", function(){\n      window.cookieconsent.initialise({\n        \"palette\": {\n          \"popup\": { \"background\": \"var(--theme-primary)\", \"text\": \"var(--theme-text)\" },\n          \"button\": { \"background\": \"var(--theme-accent)\", \"text\": \"var(--theme-text)\" }\n        },\n        \"theme\": \"classic\",\n        \"position\": \"bottom-right\",\n        \"content\": { \"message\": \"This website uses fruit cookies to ensure you get the juiciest tracking experience.\", \"dismiss\": \"Me want it!\", \"link\": \"But me wait!\", \"href\": \"https://www.youtube.com/watch?v=9PnbKL3wuH4\" }\n      })});\n  </script>\n<style>.bluegrey-lightgreen-theme{--mat-sys-background:#121316;--mat-sys-error:#ffb4ab;--mat-sys-error-container:#93000a;--mat-sys-inverse-on-surface:#2f3033;--mat-sys-inverse-primary:#005cbb;--mat-sys-inverse-surface:#e3e2e6;--mat-sys-on-background:#e3e2e6;--mat-sys-on-error:#690005;--mat-sys-on-error-container:#ffdad6;--mat-sys-on-primary:#002f65;--mat-sys-on-primary-container:#d7e3ff;--mat-sys-on-primary-fixed:#001b3f;--mat-sys-on-primary-fixed-variant:#00458f;--mat-sys-on-secondary:#283041;--mat-sys-on-secondary-container:#dae2f9;--mat-sys-on-secondary-fixed:#131c2b;--mat-sys-on-secondary-fixed-variant:#3e4759;--mat-sys-on-sur

...[truncated 7219 chars — full evidence in the evidence vault; sha256 above covers the complete artifact]
```
**Artifact SHA-256 Hash**: `a2f0a6375d937ec1dc1f8b3c5b7754430ed8786e8d7c83f33fa87d1311d9b558`
**Chain of Custody ID**: `no-audit-event`

---

### 29. Deprecated Feature-Policy Header - Detection
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
[{"type": "nuclei_finding", "template": "deprecated-feature-policy", "matched_at": "http://127.0.0.1/", "url": "http://127.0.0.1/", "request": "GET / HTTP/1.1\r\nHost: 127.0.0.1\r\nUser-Agent: Mozilla/5.0 (CentOS; Linux i686) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36\r\nConnection: close\r\nAccept: */*\r\nAccept-Language: en\r\nAccept-Encoding: gzip\r\n\r\n", "response": "HTTP/1.1 200 OK\r\nConnection: close\r\nTransfer-Encoding: chunked\r\nAccept-Ranges: bytes\r\nAccess-Control-Allow-Origin: *\r\nCache-Control: public, max-age=0\r\nContent-Type: text/html; charset=UTF-8\r\nDate: Mon, 31 Aug 2026 15:56:19 GMT\r\nEtag: W/\"26af-1a058887300\"\r\nFeature-Policy: payment 'self'\r\nLast-Modified: Mon, 31 Aug 2026 15:55:32 GMT\r\nVary: Accept-Encoding\r\nX-Content-Type-Options: nosniff\r\nX-Frame-Options: SAMEORIGIN\r\nX-Recruiting: /#/jobs\r\n\r\n<!--\n  ~ Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.\n  ~ SPDX-License-Identifier: MIT\n  -->\n\n<!doctype html>\n<html lang=\"en\" data-beasties-container>\n<head>\n  <meta charset=\"utf-8\">\n  <title>OWASP Juice Shop</title>\n  <meta name=\"description\" content=\"Probably the most modern and sophisticated insecure web application\">\n  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n  <link rel=\"preconnect\" href=\"https://fonts.googleapis.com\">\n  <link rel=\"preconnect\" href=\"https://fonts.gstatic.com\" crossorigin>\n  <style>@font-face{font-family:'VT323';font-style:normal;font-weight:400;font-display:swap;src:url(https://fonts.gstatic.com/s/vt323/v18/pxiKyp0ihIEF2isQFJXGdg.woff2) format('woff2');unicode-range:U+0102-0103, U+0110-0111, U+0128-0129, U+0168-0169, U+01A0-01A1, U+01AF-01B0, U+0300-0301, U+0303-0304, U+0308-0309, U+0323, U+0329, U+1EA0-1EF9, U+20AB;}@font-face{font-family:'VT323';font-style:normal;font-weight:400;font-display:swap;src:url(https://fonts.gstatic.com/s/vt323/v18/pxiKyp0ihIEF2isRFJXGdg.woff2) format('woff2');unicode-range:U+0100-02BA, U+02BD-02C5, U+02C7-02CC, U+02CE-02D7, U+02DD-02FF, U+0304, U+0308, U+0329, U+1D00-1DBF, U+1E00-1E9F, U+1EF2-1EFF, U+2020, U+20A0-20AB, U+20AD-20C0, U+2113, U+2C60-2C7F, U+A720-A7FF;}@font-face{font-family:'VT323';font-style:normal;font-weight:400;font-display:swap;src:url(https://fonts.gstatic.com/s/vt323/v18/pxiKyp0ihIEF2isfFJU.woff2) format('woff2');unicode-range:U+0000-00FF, U+0131, U+0152-0153, U+02BB-02BC, U+02C6, U+02DA, U+02DC, U+0304, U+0308, U+0329, U+2000-206F, U+20AC, U+2122, U+2191, U+2193, U+2212, U+2215, U+FEFF, U+FFFD;}</style>\n  <link id=\"favicon\" rel=\"icon\" type=\"image/x-icon\" href=\"assets/public/favicon_js.ico\">\n  <script>\n    window.addEventListener(\"load\", function(){\n      window.cookieconsent.initialise({\n        \"palette\": {\n          \"popup\": { \"background\": \"var(--theme-primary)\", \"text\": \"var(--theme-text)\" },\n          \"button\": { \"background\": \"var(--theme-accent)\", \"text\": \"var(--theme-text)\" }\n        },\n        \"theme\": \"classic\",\n        \"position\": \"bottom-right\",\n        \"content\": { \"message\": \"This website uses fruit cookies to ensure you get the juiciest tracking experience.\", \"dismiss\": \"Me want it!\", \"link\": \"But me wait!\", \"href\": \"https://www.youtube.com/watch?v=9PnbKL3wuH4\" }\n      })});\n  </script>\n<style>.bluegrey-lightgreen-theme{--mat-sys-background:#121316;--mat-sys-error:#ffb4ab;--mat-sys-error-container:#93000a;--mat-sys-inverse-on-surface:#2f3033;--mat-sys-inverse-primary:#005cbb;--mat-sys-inverse-surface:#e3e2e6;--mat-sys-on-background:#e3e2e6;--mat-sys-on-error:#690005;--mat-sys-on-error-container:#ffdad6;--mat-sys-on-primary:#002f65;--mat-sys-on-primary-container:#d7e3ff;--mat-sys-on-primary-fixed:#001b3f;--mat-sys-on-primary-fixed-variant:#00458f;--mat-sys-on-secondary:#283041;--mat-sys-on-secondary-container:#dae2f9;--mat-sys-on-secondary-fixed:#131c2b;--mat-sys-on-secondary-fixed-variant:#3e4759;--mat-sys-on-s

...[truncated 7173 chars — full evidence in the evidence vault; sha256 above covers the complete artifact]
```
**Artifact SHA-256 Hash**: `126a0157a645bcdaaf2fa9f6decfe672e8d68a3bf6eb59189cc5d3587558ea1a`
**Chain of Custody ID**: `no-audit-event`

---

### 30. OWASP Juice Shop
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
[{"type": "nuclei_finding", "template": "owasp-juice-shop-detect", "matched_at": "http://127.0.0.1/", "url": "http://127.0.0.1/", "request": "GET / HTTP/1.1\r\nHost: 127.0.0.1\r\nUser-Agent: Mozilla/5.0 (CentOS; Linux i686) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36\r\nConnection: close\r\nAccept: */*\r\nAccept-Language: en\r\nAccept-Encoding: gzip\r\n\r\n", "response": "HTTP/1.1 200 OK\r\nConnection: close\r\nTransfer-Encoding: chunked\r\nAccept-Ranges: bytes\r\nAccess-Control-Allow-Origin: *\r\nCache-Control: public, max-age=0\r\nContent-Type: text/html; charset=UTF-8\r\nDate: Mon, 31 Aug 2026 15:56:19 GMT\r\nEtag: W/\"26af-1a058887300\"\r\nFeature-Policy: payment 'self'\r\nLast-Modified: Mon, 31 Aug 2026 15:55:32 GMT\r\nVary: Accept-Encoding\r\nX-Content-Type-Options: nosniff\r\nX-Frame-Options: SAMEORIGIN\r\nX-Recruiting: /#/jobs\r\n\r\n<!--\n  ~ Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.\n  ~ SPDX-License-Identifier: MIT\n  -->\n\n<!doctype html>\n<html lang=\"en\" data-beasties-container>\n<head>\n  <meta charset=\"utf-8\">\n  <title>OWASP Juice Shop</title>\n  <meta name=\"description\" content=\"Probably the most modern and sophisticated insecure web application\">\n  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n  <link rel=\"preconnect\" href=\"https://fonts.googleapis.com\">\n  <link rel=\"preconnect\" href=\"https://fonts.gstatic.com\" crossorigin>\n  <style>@font-face{font-family:'VT323';font-style:normal;font-weight:400;font-display:swap;src:url(https://fonts.gstatic.com/s/vt323/v18/pxiKyp0ihIEF2isQFJXGdg.woff2) format('woff2');unicode-range:U+0102-0103, U+0110-0111, U+0128-0129, U+0168-0169, U+01A0-01A1, U+01AF-01B0, U+0300-0301, U+0303-0304, U+0308-0309, U+0323, U+0329, U+1EA0-1EF9, U+20AB;}@font-face{font-family:'VT323';font-style:normal;font-weight:400;font-display:swap;src:url(https://fonts.gstatic.com/s/vt323/v18/pxiKyp0ihIEF2isRFJXGdg.woff2) format('woff2');unicode-range:U+0100-02BA, U+02BD-02C5, U+02C7-02CC, U+02CE-02D7, U+02DD-02FF, U+0304, U+0308, U+0329, U+1D00-1DBF, U+1E00-1E9F, U+1EF2-1EFF, U+2020, U+20A0-20AB, U+20AD-20C0, U+2113, U+2C60-2C7F, U+A720-A7FF;}@font-face{font-family:'VT323';font-style:normal;font-weight:400;font-display:swap;src:url(https://fonts.gstatic.com/s/vt323/v18/pxiKyp0ihIEF2isfFJU.woff2) format('woff2');unicode-range:U+0000-00FF, U+0131, U+0152-0153, U+02BB-02BC, U+02C6, U+02DA, U+02DC, U+0304, U+0308, U+0329, U+2000-206F, U+20AC, U+2122, U+2191, U+2193, U+2212, U+2215, U+FEFF, U+FFFD;}</style>\n  <link id=\"favicon\" rel=\"icon\" type=\"image/x-icon\" href=\"assets/public/favicon_js.ico\">\n  <script>\n    window.addEventListener(\"load\", function(){\n      window.cookieconsent.initialise({\n        \"palette\": {\n          \"popup\": { \"background\": \"var(--theme-primary)\", \"text\": \"var(--theme-text)\" },\n          \"button\": { \"background\": \"var(--theme-accent)\", \"text\": \"var(--theme-text)\" }\n        },\n        \"theme\": \"classic\",\n        \"position\": \"bottom-right\",\n        \"content\": { \"message\": \"This website uses fruit cookies to ensure you get the juiciest tracking experience.\", \"dismiss\": \"Me want it!\", \"link\": \"But me wait!\", \"href\": \"https://www.youtube.com/watch?v=9PnbKL3wuH4\" }\n      })});\n  </script>\n<style>.bluegrey-lightgreen-theme{--mat-sys-background:#121316;--mat-sys-error:#ffb4ab;--mat-sys-error-container:#93000a;--mat-sys-inverse-on-surface:#2f3033;--mat-sys-inverse-primary:#005cbb;--mat-sys-inverse-surface:#e3e2e6;--mat-sys-on-background:#e3e2e6;--mat-sys-on-error:#690005;--mat-sys-on-error-container:#ffdad6;--mat-sys-on-primary:#002f65;--mat-sys-on-primary-container:#d7e3ff;--mat-sys-on-primary-fixed:#001b3f;--mat-sys-on-primary-fixed-variant:#00458f;--mat-sys-on-secondary:#283041;--mat-sys-on-secondary-container:#dae2f9;--mat-sys-on-secondary-fixed:#131c2b;--mat-sys-on-secondary-fixed-variant:#3e4759;--mat-sys-on-sur

...[truncated 7219 chars — full evidence in the evidence vault; sha256 above covers the complete artifact]
```
**Artifact SHA-256 Hash**: `ee61b7f066d1927edb2fa1247b73fad7ac5be494a2ab0f264eeb5a19c0de3bc8`
**Chain of Custody ID**: `no-audit-event`

---

### 31. SQLI via POST parameter 'username' (web_audit differential)
- **Severity**: high
- **Type**: sqli
- **Target**: unknown
- **Attack Technique**: T1190 - Exploit Public-Facing Application
- **OWASP**: A03:2021-Injection
- **CVSS**: 8.1 (High)

#### Description
web_audit differential confirmed SQLI at http://127.0.0.1:9199/login: POST parameter 'username' with probe "' OR '1'='1' --" produced a behavioral delta the control request lacked (error_signature=False, auth_bypass=True).

#### Remediation
Use parameterized queries / prepared statements; never concatenate input.


#### Proof of Concept / Evidence
```
[{"type": "web_audit_differential", "provenance": "web_audit", "url": "http://127.0.0.1:9199/login", "method": "POST", "parameter": "username", "baseline_value": "audit_probe_baseline_77", "probe": "' OR '1'='1' --", "baseline_status": 401, "injected_status": 200, "error_signature": false, "auth_bypass": true, "authenticated": false}]
```
**Artifact SHA-256 Hash**: `9b1257d4de7426d2d3c649bdbbaca57d80e70822e7a11e1ee3f4c9ba179f9895`
**Chain of Custody ID**: `no-audit-event`

---

### 32. SQLI via POST parameter 'password' (web_audit differential)
- **Severity**: high
- **Type**: sqli
- **Target**: unknown
- **Attack Technique**: T1190 - Exploit Public-Facing Application
- **OWASP**: A03:2021-Injection
- **CVSS**: 8.1 (High)

#### Description
web_audit differential confirmed SQLI at http://127.0.0.1:9199/login: POST parameter 'password' with probe "' OR '1'='1" produced a behavioral delta the control request lacked (error_signature=False, auth_bypass=True).

#### Remediation
Use parameterized queries / prepared statements; never concatenate input.


#### Proof of Concept / Evidence
```
[{"type": "web_audit_differential", "provenance": "web_audit", "url": "http://127.0.0.1:9199/login", "method": "POST", "parameter": "password", "baseline_value": "audit_probe_baseline_77", "probe": "' OR '1'='1", "baseline_status": 401, "injected_status": 200, "error_signature": false, "auth_bypass": true, "authenticated": false}]
```
**Artifact SHA-256 Hash**: `59ed63b3ab69d203a95d3cae5350fd29901db6132e1da32981ac1cafe21c468e`
**Chain of Custody ID**: `no-audit-event`

---
