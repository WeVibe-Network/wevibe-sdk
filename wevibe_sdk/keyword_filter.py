"""Keyword validation and filtering.

Defines what constitutes a valid keyword and provides filtering functions
for cleaning keyword distributions.
"""

from __future__ import annotations

import re

_VALID_TERM_RE = re.compile(r"^[a-z][a-z0-9_]{1,39}$")

_NUMERIC_RE = re.compile(r"^[\d_]+[a-z]?$|^\d+[a-z]\d*$")
_VERSION_RE = re.compile(r"^v\d+([._]\d+)*$|^\d+[a-z]\d*$")

# ── Kind reference lists ─────────────────────────────────────
# Known stack terms (technologies, libraries, platforms, languages).
# The LLM assigns kind, but known terms are overridden by these lists.
# Novel terms not in either list keep the LLM-assigned kind.

KNOWN_STACK_TERMS: set[str] = {
    # Languages
    "python",
    "javascript",
    "typescript",
    "rust",
    "golang",
    "java",
    "csharp",
    "ruby",
    "php",
    "swift",
    "kotlin",
    "scala",
    "elixir",
    "clojure",
    "haskell",
    "lua",
    "perl",
    "zig",
    "nim",
    "dart",
    # Web frameworks
    "fastapi",
    "django",
    "flask",
    "express",
    "nextjs",
    "nuxtjs",
    "remix",
    "svelte",
    "sveltekit",
    "angular",
    "react",
    "vue",
    "astro",
    "gatsby",
    "rails",
    "sinatra",
    "gin",
    "echo_framework",
    "actix",
    "axum",
    "rocket",
    "spring",
    "quarkus",
    "laravel",
    "phoenix",
    "hono",
    "elysia",
    "bun",
    # Databases
    "postgres",
    "postgresql",
    "mysql",
    "mariadb",
    "sqlite",
    "mongodb",
    "redis",
    "memcached",
    "cassandra",
    "dynamodb",
    "cockroachdb",
    "supabase",
    "firebase",
    "planetscale",
    "neon",
    "turso",
    # Vector / search
    "qdrant",
    "pinecone",
    "weaviate",
    "milvus",
    "elasticsearch",
    "opensearch",
    "typesense",
    "meilisearch",
    "algolia",
    # Message queues / streaming
    "kafka",
    "rabbitmq",
    "nats",
    "pulsar",
    "sqs",
    "sns",
    "celery",
    "bullmq",
    "sidekiq",
    # Infrastructure
    "docker",
    "kubernetes",
    "terraform",
    "ansible",
    "nginx",
    "caddy",
    "traefik",
    "envoy",
    "istio",
    "consul",
    "vault",
    # Cloud platforms
    "aws",
    "gcp",
    "azure",
    "vercel",
    "netlify",
    "railway",
    "flyio",
    "render",
    "heroku",
    "cloudflare",
    "digitalocean",
    # Libraries / tools
    "pydantic",
    "sqlalchemy",
    "prisma",
    "drizzle",
    "typeorm",
    "sequelize",
    "mongoose",
    "httpx",
    "axios",
    "requests",
    "ws",
    "socket_io",
    "graphql",
    "grpc",
    "trpc",
    "zod",
    "joi",
    "yup",
    "valibot",
    "tanstack",
    "zustand",
    "jotai",
    "redux",
    "mobx",
    "tailwind",
    "shadcn",
    # ML / AI
    "pytorch",
    "tensorflow",
    "onnx",
    "ollama",
    "openai",
    "anthropic",
    "langchain",
    "llamaindex",
    "huggingface",
    "transformers",
    "sklearn",
    "numpy",
    "pandas",
    # Testing
    "pytest",
    "jest",
    "vitest",
    "playwright",
    "cypress",
    "selenium",
    "mocha",
    "chai",
    # Auth
    "oauth",
    "jwt",
    "auth0",
    "clerk",
    "lucia",
    "nextauth",
    # DevOps / CI
    "github_actions",
    "gitlab_ci",
    "jenkins",
    "circleci",
    "argo",
    "flux",
    # Protocols / formats
    "sse",
    "websocket",
    "http2",
    "http3",
    "grpc",
    "protobuf",
    "json",
    "yaml",
    "toml",
    "msgpack",
    "avro",
    # Specific tools
    "git",
    "npm",
    "yarn",
    "pnpm",
    "pip",
    "cargo",
    "maven",
    "gradle",
    "webpack",
    "vite",
    "esbuild",
    "rollup",
    "turbopack",
    "swc",
    "babel",
    "eslint",
    "ruff",
    "prettier",
    "biome",
    "storybook",
    "chromatic",
    # Monitoring / observability
    "prometheus",
    "grafana",
    "datadog",
    "sentry",
    "opentelemetry",
    "jaeger",
    "zipkin",
    "pagerduty",
    "logstash",
    "fluentd",
    # Misc
    "stripe",
    "twilio",
    "sendgrid",
    "resend",
    "postmark",
    "s3",
    "r2",
    "minio",
    "litestream",
    "yara",
    "deberta",
    "nomic",
}

KNOWN_PATTERN_TERMS: set[str] = {
    # Architectural patterns
    "pub_sub",
    "event_sourcing",
    "cqrs",
    "saga",
    "microservices",
    "monolith",
    "serverless",
    "edge_computing",
    "sidecar",
    "service_mesh",
    "api_gateway",
    "reverse_proxy",
    "load_balancing",
    "sharding",
    "partitioning",
    "replication",
    "federation",
    "multi_tenancy",
    # Resilience patterns
    "circuit_breaker",
    "retry",
    "exponential_backoff",
    "jitter",
    "bulkhead",
    "timeout",
    "fallback",
    "dead_letter_queue",
    "idempotency",
    "backpressure",
    "throttling",
    "rate_limiting",
    "connection_pooling",
    "health_check",
    "heartbeat",
    "graceful_shutdown",
    "graceful_degradation",
    # Data patterns
    "caching",
    "cache_invalidation",
    "write_through",
    "write_behind",
    "read_through",
    "cache_aside",
    "ttl",
    "lru",
    "bloom_filter",
    "consistent_hashing",
    "optimistic_locking",
    "pessimistic_locking",
    "eventual_consistency",
    "strong_consistency",
    "change_data_capture",
    "outbox_pattern",
    # Communication patterns
    "broadcasting",
    "fan_out",
    "fan_in",
    "scatter_gather",
    "request_reply",
    "fire_and_forget",
    "long_polling",
    "streaming",
    "server_sent_events",
    "bidirectional_streaming",
    "webhook",
    "callback",
    # Concurrency patterns
    "async_await",
    "thread_pool",
    "worker_pool",
    "actor_model",
    "mutex",
    "semaphore",
    "lock_free",
    "optimistic_concurrency",
    # Security patterns
    "token_rotation",
    "token_refresh",
    "rbac",
    "abac",
    "cors",
    "csp",
    "rate_limiting",
    "ip_allowlist",
    "encryption_at_rest",
    "encryption_in_transit",
    "secret_management",
    "prompt_injection",
    # Development patterns
    "dependency_injection",
    "factory",
    "singleton",
    "observer",
    "strategy",
    "middleware",
    "decorator",
    "adapter",
    "repository",
    "unit_of_work",
    # Deployment patterns
    "blue_green",
    "canary",
    "rolling_update",
    "feature_flag",
    "ab_testing",
    "dark_launch",
    "immutable_infrastructure",
    # Data processing patterns
    "etl",
    "batch_processing",
    "stream_processing",
    "map_reduce",
    "pipeline",
    "dag",
    "windowing",
    "watermark",
    # Problem types
    "n_plus_one",
    "thundering_herd",
    "hot_spot",
    "cold_start",
    "memory_leak",
    "connection_exhaustion",
    "race_condition",
    "deadlock",
    "starvation",
    "back_pressure",
    "split_brain",
    "cascading_failure",
    # Reliability concepts
    "sla",
    "slo",
    "error_budget",
    "chaos_engineering",
    "disaster_recovery",
    "failover",
    "redundancy",
    # Misc patterns
    "pagination",
    "cursor_pagination",
    "offset_pagination",
    "debounce",
    "deduplication",
    "reconciliation",
    "migration",
    "schema_evolution",
    "versioning",
    "multi_instance",
    "connection_timeout",
    "dead_connections",
    "reconnection",
}


def validate_keyword_kinds(keywords: list[dict]) -> list[dict]:
    """Override LLM-assigned kind for known terms using reference lists.

    Known stack terms get kind="stack". Known pattern terms get kind="pattern".
    Terms in neither list keep their LLM-assigned kind. Terms in BOTH lists
    (should not happen, but defensive) default to "stack".

    Args:
        keywords: List of keyword dicts with term, weight, role, kind

    Returns:
        Same list with kind field corrected for known terms
    """
    result = []
    for kw in keywords:
        term = kw.get("term", "")
        corrected = dict(kw)
        if term in KNOWN_STACK_TERMS:
            corrected["kind"] = "stack"
        elif term in KNOWN_PATTERN_TERMS:
            corrected["kind"] = "pattern"
        if "kind" not in corrected:
            corrected["kind"] = "pattern"
        result.append(corrected)
    return result


GENERIC_TERMS = {
    "server",
    "client",
    "error",
    "errors",
    "data",
    "config",
    "configuration",
    "setup",
    "build",
    "deploy",
    "deployment",
    "test",
    "tests",
    "testing",
    "code",
    "file",
    "files",
    "function",
    "functions",
    "class",
    "module",
    "package",
    "library",
    "framework",
    "tool",
    "tools",
    "system",
    "project",
    "app",
    "application",
    "service",
    "api",
    "endpoint",
    "request",
    "response",
    "handler",
    "middleware",
    "route",
    "routes",
    "database",
    "query",
    "queries",
    "table",
    "schema",
    "model",
    "models",
    "component",
    "components",
    "page",
    "pages",
    "view",
    "views",
    "type",
    "types",
    "interface",
    "method",
    "property",
    "value",
    "values",
    "state",
    "context",
    "event",
    "events",
    "action",
    "actions",
    "input",
    "output",
    "result",
    "results",
    "status",
    "message",
    "user",
    "users",
    "name",
    "path",
    "url",
    "key",
    "keys",
    "id",
    "list",
    "array",
    "object",
    "string",
    "number",
    "boolean",
    "true",
    "false",
    "null",
    "none",
    "default",
    "new",
    "old",
    "simple",
    "clean",
    "proper",
    "basic",
    "advanced",
    "custom",
    "specific",
    "generic",
    "common",
    "standard",
    "modern",
    "lightweight",
    "heavy",
    "fast",
    "slow",
    "aggressive",
    "strict",
    "optional",
    "required",
    "important",
    "critical",
    "create",
    "read",
    "update",
    "delete",
    "get",
    "set",
    "add",
    "remove",
    "check",
    "validate",
    "verify",
    "handle",
    "handling",
    "process",
    "manage",
    "implement",
    "configure",
    "initialize",
    "start",
    "stop",
    "run",
    "load",
    "save",
    "send",
    "receive",
    "return",
    "import",
    "export",
    "pattern",
    "patterns",
    "approach",
    "strategy",
    "solution",
    "problem",
    "issue",
    "issues",
    "feature",
    "features",
    "improvement",
    "performance",
    "security",
    "reliability",
    "scalability",
    "architecture",
    "structure",
    "design",
    "workflow",
    "development",
    "production",
    "staging",
    "environment",
    "documentation",
    "example",
    "examples",
    "tutorial",
    "version",
    "migration",
    "upgrade",
    "fix",
    "patch",
    "bug",
}

SUBJECTIVE_PREFIXES = {
    "aggressive_",
    "proper_",
    "simple_",
    "basic_",
    "clean_",
    "better_",
    "correct_",
    "good_",
    "bad_",
    "real_",
}

_PROJECT_SPECIFIC_RE = re.compile(r"^_")
_FILE_EXTENSIONS = ("_ts", "_js", "_py", "_css", "_html")


def _is_project_specific(term: str) -> bool:
    """Check if term is project-specific (leading underscore or file extension suffix)."""
    if _PROJECT_SPECIFIC_RE.match(term):
        return True
    for ext in _FILE_EXTENSIONS:
        if term.endswith(ext):
            return True
    return False


def is_structurally_valid(term: str) -> bool:
    """Check if a term meets structural requirements for a keyword."""
    if not term or not isinstance(term, str):
        return False
    if len(term) < 2 or len(term) > 40:
        return False
    if not _VALID_TERM_RE.match(term):
        return False
    if _NUMERIC_RE.match(term) or _VERSION_RE.match(term):
        return False
    if term.endswith("_"):
        return False
    return True


def is_semantically_valid(term: str) -> bool:
    """Check if a term is a meaningful keyword, not noise."""
    if term in GENERIC_TERMS:
        return False
    for prefix in SUBJECTIVE_PREFIXES:
        if term.startswith(prefix):
            return False
    if _is_project_specific(term):
        return False
    segments = term.split("_")
    if len(segments) > 4:
        return False
    if all(seg in GENERIC_TERMS for seg in segments if len(seg) > 1):
        return False
    return True


def is_valid_keyword(term: str) -> bool:
    """Full validation: structural + semantic."""
    return is_structurally_valid(term) and is_semantically_valid(term)


def filter_keywords(keywords: list[dict]) -> list[dict]:
    """Filter a keyword list, removing invalid terms."""
    return [kw for kw in keywords if is_valid_keyword(kw.get("term", ""))]


def normalize_filtered(keywords: list[dict]) -> list[dict]:
    """Re-normalize keyword weights to sum to 1.0 after filtering."""
    if not keywords:
        return []
    total = sum(kw.get("weight", 0) for kw in keywords)
    if total <= 0:
        return []
    result = []
    for kw in keywords:
        result.append(
            {
                **kw,
                "weight": round(kw["weight"] / total, 6),
            }
        )
    result.sort(key=lambda x: x["weight"], reverse=True)
    return result


def scrub_keywords(keywords: list[dict]) -> list[dict]:
    """Filter + re-normalize in one step."""
    filtered = filter_keywords(keywords)
    return normalize_filtered(filtered)
