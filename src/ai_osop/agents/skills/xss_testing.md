# Cross-Site Scripting (XSS) Testing

## Procedures

### Step 1: Input Context Analysis
- Identify all points where user-controllable input is reflected in the HTML response.
- Determine the reflection context: HTML Body, Attribute, JavaScript String, or CSS.
- Identify the character set and encoding used by the application.

### Step 2: Reflected & Stored XSS Testing
- Inject basic payloads (e.g., `<script>alert(1)</script>`) to test for lack of sanitization.
- Bypass filters using different tags (`<img>`, `<a>`, `<iframe>`) and events (`onerror`, `onmouseover`).
- Test for Stored XSS by submitting payloads to profiles, comments, and other persistent stores.

### Step 3: DOM-Based XSS & Client-Side Logic
- Analyze client-side JavaScript for dangerous sinks (e.g., `eval()`, `innerHTML`, `document.write()`).
- Trace data from sources (e.g., `location.hash`, `window.name`) to identified sinks.
- Identify and exploit flaws in client-side routing and state management.

### Step 4: Bypassing Protections (CSP & WAF)
- Audit the Content Security Policy (CSP) for weak directives (e.g., `unsafe-inline`, `unsafe-eval`).
- Attempt to bypass CSP using JSONP endpoints, script gadgets, or base tag injection.
- Use encoding and obfuscation to bypass Web Application Firewalls (WAFs).
