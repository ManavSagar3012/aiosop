from neo4j import GraphDatabase

driver = GraphDatabase.driver('bolt://localhost:7687', auth=('neo4j', 'password'))
with driver.session() as s:
    res = s.run("MATCH (t:Task {engagement_id: 'eng-20260616111630-ai-osop-full-mission-2'}) RETURN t.id as id, t.type as type, t.status as status")
    for r in res:
        print(f"{r['id']}: {r['type']} - {r['status']}")
