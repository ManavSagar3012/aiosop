from neo4j import GraphDatabase

driver = GraphDatabase.driver('bolt://localhost:7687', auth=('neo4j', 'password'))
with driver.session() as s:
    eid = 'eng-20260616111630-ai-osop-full-mission-2'
    
    def count(label):
        res = s.run(f"MATCH (n:{label} {{engagement_id: '{eid}'}}) RETURN count(n) as c")
        return res.single()['c']
        
    print(f"Tasks: {count('Task')}")
    print(f"Workflows: {count('Workflow')}")
    print(f"Steps: {count('Step')}")
    print(f"APIEndpoints: {count('APIEndpoint')}")
    print(f"Evidence: {count('Evidence')}")
    print(f"Vulnerabilities: {count('Vulnerability')}")
    res_w = s.run(f"MATCH (n:Workflow {{engagement_id: '{eid}'}}) RETURN n.id as id")
    for r in res_w:
        print(f"Workflow ID: {r['id']}")
