import httpx
import json

def test():
    payload = {
        "tool_name": "send_to_repeater",
        "request_id": "test-1",
        "url": "https://ginandjuice.shop/test-ai",
        "method": "POST",
        "body": "id=1",
        "tab_name": "AI-TEST-TAB"
    }
    
    # The Burp MCP server expects the exact string parameters, sometimes it parses poorly if not strictly formatted.
    # We will send it as raw JSON.
    r = httpx.post("http://localhost:8081/mcp/execute", data=json.dumps(payload))
    print(r.status_code)
    print(r.text)

if __name__ == "__main__":
    test()
