"""Context-Aware Remediation Engine.

The assessment's Medium-term Priority 2: match vulnerability fixes with
the target's tech fingerprint to provide developers with concrete secure
code snippets for remediation. A human researcher provides framework-
specific advice — "use Django's ORM parameterized queries" vs "use
SQLAlchemy's text() with bound parameters".

This module generates framework-specific remediation code blocks based
on the detected technology stack, which the bounty report renderer
injects into the Remediation section.
"""

from __future__ import annotations

from typing import Dict, List, Optional


# Framework-specific remediation code snippets per vuln type.
# Each entry is a dict of {framework: (code_block, description)}.
_FRAMEWORK_REMEDIATION = {
    "sqli": {
        "django": (
            "```python\n# Use Django ORM — it parameterizes automatically\n"
            "User.objects.filter(email=email_var)\n"
            "# NEVER: User.objects.raw(f\"SELECT * FROM users WHERE email='{email_var}'\")\n```",
            "Django's ORM uses parameterized queries by default. Never use raw() "
            "with f-strings or string concatenation.",
        ),
        "flask": (
            "```python\n# Use SQLAlchemy with bound parameters\n"
            'db.session.execute(text("SELECT * FROM users WHERE email = :email"), '
            '{"email": email_var})\n```',
            "SQLAlchemy's text() with named parameters is safe. Never use f-strings "
            "in SQL text.",
        ),
        "spring": (
            "```java\n// Use JPA/Hibernate with parameterized queries\n"
            '@Query("SELECT u FROM User u WHERE u.email = :email")\n'
            'User findByEmail(@Param("email") String email);\n```',
            "Spring Data JPA parameterizes automatically. Never concatenate input "
            "into @Query strings.",
        ),
        "express": (
            "```javascript\n// Use parameterized queries with your DB driver\n"
            "db.query('SELECT * FROM users WHERE email = $1', [emailVar]);\n```",
            "pg/mysql2 drivers support parameterized queries with $1/? placeholders. "
            "Never use string concatenation.",
        ),
        "php": (
            "```php\n// Use PDO with prepared statements\n"
            "$stmt = $pdo->prepare('SELECT * FROM users WHERE email = :email');\n"
            "$stmt->execute(['email' => $emailVar]);\n```",
            "PDO prepared statements parameterize automatically. Never use "
            "mysqli_query with string interpolation.",
        ),
        "rails": (
            "```ruby\n# Use ActiveRecord parameterized queries\n"
            "User.where(email: email_var)\n# NEVER: User.where(\"email = '#{email_var}'\")\n```",
            "ActiveRecord parameterizes when using hash syntax. Never use string "
            "interpolation in where clauses.",
        ),
        "aspnet": (
            "```csharp\n// Use Entity Framework parameterized queries\n"
            "var user = context.Users.Where(u => u.Email == emailVar).FirstOrDefault();\n"
            '// NEVER: context.Database.SqlQuery<User>("SELECT * FROM Users WHERE Email=\'" + emailVar + "\'")\n```',
            "Entity Framework LINQ parameterizes automatically. Never use "
            "SqlQuery with string concatenation.",
        ),
    },
    "xss": {
        "django": (
            "```python\n# Django templates auto-escape by default\n"
            "{{ user_input }}  {# safe — auto-escaped #}\n"
            "{# NEVER use |safe filter on untrusted input #}\n```",
            "Django templates auto-escape HTML. Never use the |safe filter on "
            "user input. Use mark_safe() only on trusted content.",
        ),
        "react": (
            "```jsx\n// React auto-escapes by default\n"
            "<div>{userInput}</div>  // safe\n"
            "// NEVER: <div dangerouslySetInnerHTML={{__html: userInput}} />\n```",
            "React auto-escapes JSX expressions. Never use dangerouslySetInnerHTML "
            "with untrusted input.",
        ),
        "vue": (
            "```vue\n<!-- Vue auto-escapes by default -->\n"
            "<div>{{ userInput }}</div>  <!-- safe -->\n"
            '<!-- NEVER: <div v-html="userInput"></div> -->\n```',
            "Vue auto-escapes interpolation. Never use v-html with untrusted input.",
        ),
        "express": (
            "```javascript\n// Use a templating engine that auto-escapes (EJS, Pug)\n"
            "<%= userInput %>  // EJS auto-escapes\n"
            "// NEVER: <%- userInput %>  // EJS unescaped\n```",
            "Use EJS/Pug auto-escaping. Never use the unescaped output (<%-) on "
            "untrusted input.",
        ),
        "php": (
            "```php\n// Use htmlspecialchars on output\n"
            "echo htmlspecialchars($userInput, ENT_QUOTES, 'UTF-8');\n```",
            "Always call htmlspecialchars() with ENT_QUOTES on untrusted output.",
        ),
    },
    "ssrf": {
        "django": (
            "```python\n# Validate and allow-list URLs\n"
            "from urllib.parse import urlparse\n"
            "parsed = urlparse(user_url)\n"
            "if parsed.hostname not in ALLOWED_HOSTS:\n"
            "    raise ValueError('blocked')\n"
            "# Block link-local/metadata ranges\n"
            "import ipaddress\n"
            "ip = ipaddress.ip_address(socket.gethostbyname(parsed.hostname))\n"
            "if ip.is_private or ip.is_loopback:\n"
            "    raise ValueError('blocked')\n```",
            "Validate the URL scheme + hostname against an allow-list. Block "
            "private/loopback/link-local IP ranges.",
        ),
        "flask": (
            "```python\n# Same pattern as Django — validate URL before fetching\n"
            "from urllib.parse import urlparse\n"
            "import ipaddress, socket\n"
            "def is_safe_url(url):\n"
            "    p = urlparse(url)\n"
            "    if p.scheme not in ('http', 'https'): return False\n"
            "    ip = ipaddress.ip_address(socket.gethostbyname(p.hostname))\n"
            "    return not (ip.is_private or ip.is_loopback or ip.is_link_local)\n```",
            "Validate URL scheme + resolve hostname to check IP range before fetching.",
        ),
    },
    "jwt_abuse": {
        "django": (
            "```python\n# Pin the algorithm; reject 'none'\n"
            "import jwt\n"
            "token = jwt.decode(jwt_token, SECRET_KEY, algorithms=['HS256'])\n"
            "# NEVER: jwt.decode(jwt_token, SECRET_KEY, algorithms=None)\n```",
            "Always specify the expected algorithms list explicitly. Never pass "
            "algorithms=None (allows 'none').",
        ),
        "express": (
            "```javascript\n// Pin the algorithm in jsonwebtoken\n"
            "jwt.verify(token, secret, { algorithms: ['HS256'] });\n"
            "// NEVER: jwt.verify(token, secret)  // allows 'none'\n```",
            "Always specify algorithms in the verify options. Never omit it.",
        ),
    },
    "mass_assignment": {
        "django": (
            "```python\n# Use ModelForm / Serializer with explicit fields\n"
            "class UserSerializer(serializers.ModelSerializer):\n"
            "    class Meta:\n"
            "        model = User\n"
            "        fields = ['email', 'password']  # NOT: '__all__'\n```",
            "Explicitly list allowed fields in serializers/forms. Never use "
            "__all__ on models with privileged fields.",
        ),
        "rails": (
            "```ruby\n# Use strong parameters\n"
            "def user_params\n"
            "  params.require(:user).permit(:email, :password)\n"
            "  # NOT: params[:user]  # mass assignment\n"
            "end\n```",
            "Always use strong_parameters permit() with an explicit allow-list.",
        ),
        "spring": (
            "```java\n// Use DTO with explicit fields; never bind entity directly\n"
            "@PostMapping\n"
            "public User create(@RequestBody UserDTO dto) {\n"
            "    // UserDTO only has email, password — not role/isAdmin\n"
            "}\n```",
            "Use a dedicated DTO with only the fields the user should set. Never "
            "bind the entity directly.",
        ),
        "express": (
            "```javascript\n// Explicitly pick allowed fields\n"
            "const { email, password } = req.body;\n"
            "// NEVER: const user = new User(req.body);  // mass assignment\n"
            "const user = new User({ email, password });\n```",
            "Destructure only the allowed fields from the request body. Never pass "
            "req.body directly to a model constructor.",
        ),
    },
    "csrf": {
        "django": (
            "```python\n# Django has built-in CSRF protection\n"
            "{% csrf_token %}  {# in every form #}\n"
            "# MIDDLEWARE includes CsrfViewMiddleware by default\n```",
            "Django's CsrfViewMiddleware is on by default. Ensure {% csrf_token %} "
            "is in every form.",
        ),
        "flask": (
            "```python\n# Use Flask-WTF\n"
            "from flask_wtf.csrf import CSRFProtect\n"
            "csrf = CSRFProtect(app)\n"
            "# Add {{ csrf_token() }} in forms\n```",
            "Use Flask-WTF's CSRFProtect. Include csrf_token() in every form.",
        ),
        "express": (
            "```javascript\n// Use csurf middleware\n"
            "const csrf = require('csurf');\n"
            "app.use(csrf({ cookie: true }));\n"
            "// Send _csrf token to frontend\n```",
            "Use the csurf middleware and include the token in forms/AJAX headers.",
        ),
    },
}


def get_framework_remediation(
    vuln_type: str,
    frameworks: List[str],
) -> Optional[Dict[str, str]]:
    """Get framework-specific remediation code for a vuln type.

    Args:
        vuln_type: the vulnerability type string (e.g. 'sqli', 'xss')
        frameworks: detected frameworks (e.g. ['django', 'react'])

    Returns:
        Dict with 'code' and 'description' keys, or None if no
        framework-specific remediation is available.
    """
    vuln_remediation = _FRAMEWORK_REMEDIATION.get(vuln_type)
    if not vuln_remediation:
        return None

    for fw in frameworks:
        fw_lower = fw.lower()
        # Check direct match
        if fw_lower in vuln_remediation:
            code, desc = vuln_remediation[fw_lower]
            return {"code": code, "description": desc, "framework": fw_lower}

        # Check aliases
        aliases = {
            "python": ["django", "flask"],
            "java": ["spring"],
            "javascript": ["express"],
            "node": ["express"],
            "nodejs": ["express"],
            "ruby": ["rails"],
            "c#": ["aspnet"],
        }
        for alias, fw_keys in aliases.items():
            if alias in fw_lower:
                for fk in fw_keys:
                    if fk in vuln_remediation:
                        code, desc = vuln_remediation[fk]
                        return {"code": code, "description": desc, "framework": fk}

    return None
