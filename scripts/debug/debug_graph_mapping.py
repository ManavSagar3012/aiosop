import asyncio
from ai_osop.memory.graph_memory import GraphMemory
from ai_osop.core.models import WorkflowStep
import uuid

async def test_graph():
    graph = GraphMemory()
    await graph.connect()
    
    sid = 'eng-20260613054201-syfe-live-engagement'
    # Use an existing workflow ID from previous telemetry
    w_id = 'wf-74c76825fd5b'
    # Use an existing endpoint ID
    e_id = 'ep-08b11a956cc1'
    
    step = WorkflowStep(
        workflow_id=w_id,
        endpoint_id=e_id,
        order=1,
        action_type="TEST",
        engagement_id=sid
    )
    
    print(f"Attempting to add step {step.id} to workflow {w_id}...")
    try:
        res_id = await graph.add_workflow_step(step)
        print(f"SUCCESS: Created step {res_id}")
    except Exception as e:
        print(f"FAILURE: {type(e).__name__}: {e}")
        import traceback
        traceback.print_exc()
    
    await graph.close()

if __name__ == "__main__":
    asyncio.run(test_graph())
