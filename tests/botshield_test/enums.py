"""Single source of truth for the decision-log / metric enums.

Kept 1:1 with the values emitted by the module at runtime. A new
enum added on one side without the other is exactly the class of
drift that M9.2 catches — this module lets every test import the
same tuple instead of hand-rolling it.
"""

TIERS = ("none", "pass", "silent", "form", "captcha")

OUTCOMES = (
    "declined",
    "challenged",
    "verified",
    "rejected",
    "failopen",
    "rate_limited",
    "inflight_capped",
    "pending_missing",
    "misconfigured",
    "debug",
)

COOKIES = ("ok", "expired", "bad_sig", "bad_format", "absent")

# Provider names as the Prometheus counter metric suffix (underscore
# form). The decision log's `provider=` field uses the hyphenated
# form for recaptcha variants — `provider_log()` converts.
PROVIDERS = (
    "turnstile",
    "hcaptcha",
    "recaptcha_v2",
    "recaptcha_v3",
    "friendly",
    "geetest",
)


def provider_log(metric_name: str) -> str:
    """Convert the metric suffix (`recaptcha_v2`) to the decision-log
    spelling (`recaptcha-v2`). All other providers round-trip
    unchanged."""
    return metric_name.replace("recaptcha_v", "recaptcha-v")
