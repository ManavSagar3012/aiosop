import httpx
import json

def test():
    payload = {
        "tool_name": "intruder_attack",
        "request_id": "test-2",
        "url": "https://ginandjuice.shop/test-intruder",
        "method": "POST",
        "body": "search=test",
        "tab_name": "AI-INTRUDER-MANUAL"
    }
    
    r = httpx.post("http://localhost:8081/mcp/execute", data=json.dumps(payload))
    print(r.status_code)
    print(r.text)

if __name__ == "__main__":
    test()
