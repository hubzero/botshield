"""Single source of truth for the decision-log / metric enums.

Kept 1:1 with the values emitted by the module at runtime. A new
enum added on one side without the other is exactly the class of
drift that M9.2 catches — this module lets every test import the
same tuple instead of hand-rolling it.
"""

# Tier names as the Prometheus counter metric suffix (underscore
# form). The decision log's `tier=` field spells non-interactive with
# a hyphen; `tier_log()` converts. Prometheus metric names may only
# contain [a-zA-Z0-9_:], so the two spellings cannot be unified --
# same split the providers below already have.
TIERS = ("none", "pass", "non_interactive", "interactive", "captcha",
         "safeguard")


def tier_log(tier):
    """Metric suffix -> decision-log spelling."""
    return tier.replace("_", "-")


OUTCOMES = (
    "allow",
    "challenged",
    "verified",
    "block",
    "redirect",
    "failopen",
    "rate_limited",
    "inflight_capped",
    "pending_missing",
    "misconfigured",
    "debug",
    # Counterfactual outcomes emitted under BotShieldEnabled LogOnly.
    # Leading tilde marks "real action was allow; this is what *would*
    # have happened under enforce". Per-family *_observed_total
    # counters carry the staging-volume signal; outcome counters bump
    # the original `allow` slot.
    "~challenge",
    "~block",
    "~rate_limited",
)

COOKIES = ("ok", "expired", "bad_sig", "bad_format", "absent", "minted")

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
