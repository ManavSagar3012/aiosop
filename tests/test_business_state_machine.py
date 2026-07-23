import pytest
from ai_osop.core.business_state_machine import LogicalBusinessStateMachine


def test_reconstruct_transitions():
    # Setup mock steps representing a Cart -> Payment flow
    steps = [
        {"url": "http://target.test/cart", "method": "GET", "action_type": "VIEW", "order": 0},
        {"url": "http://target.test/checkout/pay", "method": "POST", "action_type": "SUBMIT", "order": 1},
        {"url": "http://target.test/order/confirm", "method": "GET", "action_type": "CONFIRM", "order": 2},
    ]
    
    lbsm = LogicalBusinessStateMachine(steps)
    transitions = lbsm.reconstruct_transitions()
    
    assert len(transitions) == 2
    assert transitions[0]["from_url"] == "http://target.test/cart"
    assert transitions[0]["to_url"] == "http://target.test/checkout/pay"
    assert transitions[0]["to_method"] == "POST"


def test_generate_bypass_payloads():
    steps = [
        {"url": "http://target.test/cart", "method": "GET", "action_type": "VIEW", "order": 0},
        {"url": "http://target.test/checkout/pay", "method": "POST", "action_type": "SUBMIT", "order": 1},
        {"url": "http://target.test/admin/dashboard", "method": "GET", "action_type": "VIEW", "order": 2},
    ]
    
    lbsm = LogicalBusinessStateMachine(steps)
    payloads = lbsm.generate_bypass_payloads()
    
    # We should have jump-ahead, parameter injection, and gateway bypass payloads
    assert len(payloads) >= 3
    
    strategies = [p["strategy"] for p in payloads]
    assert "jump_ahead_bypass" in strategies
    assert "negative_parameter_injection" in strategies
    assert "header_override_bypass" in strategies
    
    # Check that payloads contain concrete request keys (url, method, headers, json)
    jump_ahead = next(p for p in payloads if p["strategy"] == "jump_ahead_bypass")
    assert jump_ahead["request"]["url"] == "http://target.test/checkout/pay"
    assert jump_ahead["request"]["method"] == "POST"
    assert "X-Bypass-Test" in jump_ahead["request"]["headers"]
