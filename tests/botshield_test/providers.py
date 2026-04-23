"""Per-provider specs for the parametrized captcha tests.

One `ProviderSpec` per provider; every quirk (body field name, OK
test token, siteverify reachability probe, optional env-var OK
token) lives in data, not in test code. A new provider is one dict
entry plus one line in `ALL`.
"""

from __future__ import annotations

import os
from dataclasses import dataclass


@dataclass(frozen=True)
class ProviderSpec:
    # Metric-suffix form (underscored). Decision log uses the
    # hyphenated form for reCAPTCHA variants — computed below.
    name: str
    demo_path: str                  # e.g. "captcha-demo", "hcaptcha-demo"
    verify_slug: str                # last segment of /botshield/captcha-verify/<slug>
    body_field: str                 # form field the module reads for the token
    ok_token: str | None            # token that verifies OK (None = no test key)
    bad_secret_file: str | None     # secret path to swap in for the REJECTED test
    good_secret_file: str | None    # matching "real" secret (to swap back)
    real_token_env: str | None      # env var providing a real OK token
    siteverify_probe: str           # URL we can reach to check the provider is up

    @property
    def log_name(self) -> str:
        """Provider value as it appears in the `provider=` log field."""
        return self.name.replace("recaptcha_v", "recaptcha-v")

    @property
    def verify_path(self) -> str:
        return f"/botshield/captcha-verify/{self.verify_slug}"

    def real_token(self) -> str | None:
        """Return the real OK token if the env var is set, else None."""
        if not self.real_token_env:
            return None
        return os.environ.get(self.real_token_env) or None


TURNSTILE = ProviderSpec(
    name="turnstile",
    demo_path="captcha-demo",
    verify_slug="turnstile",
    body_field="cf-turnstile-response",
    # Cloudflare's published always-pass site+secret pair: any token
    # string validates. The dev vhost ships with the matching
    # publicly-documented secret.
    ok_token="x",
    bad_secret_file="/etc/botshield/turnstile-fail-secret",
    good_secret_file="/etc/botshield/turnstile-secret",
    real_token_env=None,
    siteverify_probe="https://challenges.cloudflare.com/turnstile/v0/siteverify",
)

HCAPTCHA = ProviderSpec(
    name="hcaptcha",
    demo_path="hcaptcha-demo",
    verify_slug="hcaptcha",
    body_field="h-captcha-response",
    # hCaptcha's always-pass sitekey requires this canonical test
    # token (unlike Turnstile, the string matters).
    ok_token="10000000-aaaa-bbbb-cccc-000000000001",
    # hCaptcha doesn't need a secret swap for REJECTED — any token
    # other than the canonical one yields invalid-input-response.
    bad_secret_file=None,
    good_secret_file=None,
    real_token_env=None,
    siteverify_probe="https://api.hcaptcha.com/siteverify",
)

RECAPTCHA_V2 = ProviderSpec(
    name="recaptcha_v2",
    demo_path="recaptcha-v2-demo",
    verify_slug="recaptcha-v2",
    body_field="g-recaptcha-response",
    # Google's published test keypair: any token validates.
    ok_token="x",
    bad_secret_file="/etc/botshield/recaptcha-v2-badsecret",
    good_secret_file="/etc/botshield/recaptcha-v2-secret",
    real_token_env=None,
    siteverify_probe="https://www.google.com/recaptcha/api/siteverify",
)

RECAPTCHA_V3 = ProviderSpec(
    name="recaptcha_v3",
    demo_path="recaptcha-v3-demo",
    verify_slug="recaptcha-v3",
    body_field="g-recaptcha-response",
    ok_token=None,  # no published test keys
    bad_secret_file=None,
    good_secret_file=None,
    real_token_env="BS_RECAPTCHA_V3_TOKEN",
    siteverify_probe="https://www.google.com/recaptcha/api/siteverify",
)

FRIENDLY = ProviderSpec(
    name="friendly",
    demo_path="friendly-demo",
    verify_slug="friendly",
    body_field="frc-captcha-solution",  # the odd one out
    ok_token=None,
    bad_secret_file=None,
    good_secret_file=None,
    real_token_env="BS_FRIENDLY_SOLUTION",
    siteverify_probe="https://api.friendlycaptcha.com/api/v1/siteverify",
)

GEETEST = ProviderSpec(
    name="geetest",
    demo_path="geetest-demo",
    verify_slug="geetest",
    body_field="geetest-token",
    ok_token=None,
    bad_secret_file=None,
    good_secret_file=None,
    real_token_env="BS_GEETEST_TOKEN",
    # GeeTest's siteverify is gcaptcha4.geetest.com; the doc host is
    # https://gcaptcha4.geetest.com/validate — reachability there is
    # the right probe.
    siteverify_probe="https://gcaptcha4.geetest.com/validate",
)

ALL: tuple[ProviderSpec, ...] = (
    TURNSTILE, HCAPTCHA, RECAPTCHA_V2, RECAPTCHA_V3, FRIENDLY, GEETEST,
)

WITH_OK_TOKEN: tuple[ProviderSpec, ...] = tuple(
    p for p in ALL if p.ok_token is not None
)

WITH_SECRET_SWAP: tuple[ProviderSpec, ...] = tuple(
    p for p in ALL if p.bad_secret_file is not None
)
