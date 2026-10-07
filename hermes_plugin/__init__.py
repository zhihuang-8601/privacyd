"""Hermes plugin entry point: `register(ctx)`."""

from __future__ import annotations

import logging

from .middleware import PrivacyMiddleware, blocked_request

__all__ = ["PrivacyMiddleware", "blocked_request", "register"]

log = logging.getLogger("privacy-gateway")


def register(ctx) -> None:
    middleware = None
    try:
        middleware = PrivacyMiddleware()
        callback = middleware.on_llm_request
    except Exception as exc:
        # Misconfiguration must not silently disable protection: block every request.
        log.error("privacy-gateway misconfigured (%s); blocking all model requests",
                  type(exc).__name__)

        def callback(**kwargs):
            return {"request": blocked_request(kwargs.get("request"), "privacy_gateway_misconfigured"),
                    "source": "privacy-gateway", "reason": "blocked: misconfigured"}

    # Required: outbound scrubbing.
    ctx.register_middleware("llm_request", callback)

    # Optional: local-only restoration of placeholders (review G1). If this Hermes cannot
    # register them, placeholders simply stay, which is safe.
    if middleware is not None:
        try:
            ctx.register_middleware("tool_request", middleware.on_tool_request)
            ctx.register_hook("transform_llm_output", middleware.on_llm_output)
        except Exception as exc:
            log.warning("privacy-gateway: placeholder restoration unavailable (%s)", type(exc).__name__)
