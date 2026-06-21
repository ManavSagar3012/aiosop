import httpx
import asyncio

async def create_syfe_engagement():
    url = "http://127.0.0.1:8200/engagements"
    headers = {
        "Authorization": "Bearer dev-token",
        "Content-Type": "application/json"
    }
    payload = {
        "engagement_id": "syfe-live-mission-v2",
        "domains": ["uat-bugbounty.nonprod.syfe.com"],
        "roe": {
            "max_depth": 3,
            "scan_intensity": "normal"
        },
        "allowed_techniques": ["recon", "vuln_scan", "browser_navigation"]
    }
    
    async with httpx.AsyncClient() as client:
        r = await client.post(url, json=payload, headers=headers)
        if r.status_code == 200:
            print(f"Created engagement: {r.json()['session_id']}")
            session_id = r.json()['session_id']
            
            # Transition to reconnaissance
            r2 = await client.post(f"{url}/{session_id}/transition?new_phase=reconnaissance", headers=headers)
            if r2.status_code == 200:
                print(f"Transitioned to reconnaissance: {session_id}")
            else:
                print(f"Failed to transition: {r2.text}")
        else:
            print(f"Failed to create engagement: {r.text}")

if __name__ == "__main__":
    asyncio.run(create_syfe_engagement())
