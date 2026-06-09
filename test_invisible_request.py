import httpx
import json

def test_invisible_request():
    payload = {
        "tool_name": "send_http_request",
        "request_id": "test-invisible-1",
        "url": "https://ginandjuice.shop/api/health",
        "method": "GET",
        "body": ""
    }
    
    print(f"Executing invisible HTTP request via Burp MCP...")
    r = httpx.post("http://localhost:8081/mcp/execute", data=json.dumps(payload))
    
    print(f"Status Code: {r.status_code}")
    try:
        response_json = r.json()
        print("Response from Burp MCP:")
        print(json.dumps(response_json, indent=2))
        
        # Highlight the exact server response
        if "result" in response_json and "response_body" in response_json["result"]:
            print("\n--- Raw Server Response Body ---")
            print(response_json["result"]["response_body"].replace("\\n", "\n"))
            print("--------------------------------")
    except json.JSONDecodeError:
        print("Raw text response:")
        print(r.text)

if __name__ == "__main__":
    test_invisible_request()
