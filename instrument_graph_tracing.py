import os, re
os.chdir('C:/Users/HP/OneDrive/Desktop/burp_mcp/ai-osop')

with open('src/ai_osop/memory/graph_memory.py', 'r', encoding='utf-8') as f:
    content = f.read()

methods_to_instrument = [
    'find_attack_paths', 'get_graph_stats', 'get_attack_surface',
    'propagate_risk', 'get_node_details', 'get_endpoint_url_for_vulnerability',
    'reset_interrupted_tasks', 'find_incomplete_chains', 'task_has_spawned',
    'link_task_dependency', 'query_graph', 'add_asset', 'add_endpoint',
    'add_vulnerability', 'upsert_task', 'add_evidence', 'get_evidence',
    'get_findings', 'update_vulnerability', 'add_workflow_node',
    'add_api_endpoint', 'link_vulnerability_to_endpoint', 'link_vulnerability_to_asset',
    'get_attack_surface_for_vulnerability', 'get_path_to_exploitation',
    'get_api_endpoints', 'get_vulnerabilities_for_endpoint', 'get_workflow_nodes',
    'get_exploitation_path', 'get_risk_summary', 'get_node_by_id', 'get_relationships',
    'get_attack_path', 'get_vulnerability_chain', 'get_exploitation_summary',
]

for method_name in methods_to_instrument:
    pattern = r'(async def ' + method_name + r'\([^)]*\)(?:\s*->\s*[^:]*?)?:\s*\n)'
    match = re.search(pattern, content)
    if not match:
        continue
    method_start = match.end()
    next_def = re.search(r'\n    async def |\n    def |\nclass |\Z', content[method_start:])
    method_end = method_start + next_def.start() if next_def else len(content)
    method_body = content[method_start:method_end]
    if 'trace_span' in method_body:
        continue
    # Find first async with self._driver.session() or first non-empty line
    session_match = re.search(r'async with self\._driver\.session\(\) as (\w+):', method_body)
    if session_match:
        session_line = session_match.group(0)
        indent = session_match.group(0)[:len(session_match.group(0)) - len(session_match.group(0).lstrip())]
        wrapped = indent + 'with trace_span("graph_memory.' + method_name + '", attributes={"engagement_id": engagement_id}):\n' + indent + '    ' + session_line.lstrip() + '\n'
        new_body = method_body.replace(session_line + '\n', wrapped, 1)
        content = content[:method_start] + new_body + content[method_end:]
    else:
        # find first non-empty line
        lines = method_body.split('\n')
        first_code = None
        for i, line in enumerate(lines):
            if line.strip() != '' and not line.strip().startswith('"""') and not line.strip().startswith("'''"):
                first_code = i
                break
        if first_code is None:
            continue
        line = lines[first_code]
        indent = line[:len(line) - len(line.lstrip())]
        new_line = indent + 'with trace_span("graph_memory.' + method_name + '", attributes={"engagement_id": engagement_id}):\n' + indent + '    ' + line.lstrip() + '\n'
        lines[first_code] = new_line
        # indent everything after first_code by 4 spaces
        for i in range(first_code+1, len(lines)):
            if lines[i].strip() != '' and not lines[i].startswith('#'):
                lines[i] = '    ' + lines[i]
        new_body = '\n'.join(lines)
        content = content[:method_start] + new_body + content[method_end:]

with open('src/ai_osop/memory/graph_memory.py', 'w', encoding='utf-8') as f:
    f.write(content)

print('graph_memory.py trace_span instrumentation completed')
