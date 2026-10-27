"""litaudit — zero-dependency security auditor for LiteLLM / LLM-gateway config files.

Static-audits config.yaml files of LiteLLM proxy deployments (and similar
LLM gateway configs) for the classes of misconfiguration that have caused
real-world breaches: hardcoded master keys, literal provider API keys,
credential-bearing database URLs, missing spend controls, wildcard model
routes, plaintext endpoints, and silent telemetry.

Only the Python standard library is used.
"""

__version__ = "1.0.0"

from .scanner import scan_config, Finding, SEVERITY_ORDER

__all__ = ["scan_config", "Finding", "SEVERITY_ORDER", "__version__"]
