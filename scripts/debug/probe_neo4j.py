import time
from neo4j import GraphDatabase

def probe_neo4j():
    start = time.time()
    try:
        driver = GraphDatabase.driver("bolt://localhost:7687", auth=("neo4j", "password"))
        with driver.session() as s:
            s.run("RETURN 1")
        print(f'Neo4j Bolt Latency: {(time.time() - start)*1000:.2f}ms')
        driver.close()
    except Exception as e:
        print(f"Neo4j Probing FAILED: {e}")

if __name__ == "__main__":
    probe_neo4j()
