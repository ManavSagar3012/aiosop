# Testing for XSS Vulnerabilities

## Workflow

### Step 1: Input and Output Mapping
- **Reflected inputs**: Test URL parameters, search fields, etc.
- **Stored inputs**: Identify persistent storage points (profiles, comments).
- **DOM inputs**: location.hash, document.referrer, etc.

### Step 2: Reflected XSS Testing
- **HTML body**: `<script>alert(document.domain)</script>`
- **HTML attribute**: `" onfocus=alert(1) autofocus="`
- **JavaScript string**: `';alert(1)//`

### Step 3: Stored XSS Testing
- Submit payloads to every stored input field.
- Check all locations where input is rendered.
- Use blind XSS payloads for internal panels.

### Step 4: DOM-Based XSS Testing
- Search JS for sources: `document.location`, `window.name`.
- Search for sinks: `innerHTML`, `eval()`, `setTimeout()`.

### Step 5: CSP Bypass
- Review CSP headers for `unsafe-inline`, `unsafe-eval`.
- Use JSONP bypass if applicable.
