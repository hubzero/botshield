"""E8.2 — module-to-app reputation export via signed X-Botshield-Claims.

Mirror of E5 in shape: signed envelope, shared
BotShieldAppIntegrationSecretFile key (one secret covers both
inbound feedback and outbound claims; cross-replay is blocked by
parser-level domain separation, not key separation). The strip
discipline is the trust anchor for apps that don't bother with HMAC.
Wire format:

    X-Botshield-Claims: v=1;score=<n>;tier=<t>;cookie=<s>;flags=<names>;
                        passes=s=<n>,f=<n>,c=<n>;ts=<unix>;sig=<64 hex>

Backend handlers normally see request headers but don't echo them in
response bodies. We use mod_headers `Header echo X-Botshield-.*`
which copies matching request headers into the response. Our
bs_handler sets X-Botshield-Claims (and strips any forged X-Botshield-*)
before the handler chain reaches mod_headers, so the response carries
exactly what the backend would have seen.

Secret is fixed in `tests/setup/provision.sh`
(/etc/botshield/app-integration-secret), same bytes shared with
test_app_feedback.py.
"""

from __future__ import annotations

import hashlib
import hmac
import re

import pytest

from botshield_test import client


pytestmark = pytest.mark.serial


SECRET_PATH = "/etc/botshield/app-integration-secret"
SECRET = b"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

PASS_UA = "Mozilla/5.0 (X11; Linux x86_64) Gecko/20100101 Firefox/125.0"
PASS_AL = "en-US,en;q=0.9"


def _g(path, **kw):
    """A claims emission requires the request to reach BS_TIER_PASS.
    The default UA + Accept-Language combo gets us there cleanly."""
    return client.get(path, ua=PASS_UA, accept_language=PASS_AL, **kw)


def _cfg_on(extra: str = "") -> str:
    return (
        'BotShieldAllow on\n'
        '    BotShieldAppClaims on\n'
        f'    BotShieldAppIntegrationSecretFile {SECRET_PATH}\n'
        # mod_headers echo: copy any X-Botshield-* request header
        # into the response so pytest can observe what the backend
        # would have seen.
        '    Header echo "X-Botshield-.*"\n'
        + extra
    )


def _verify(value: str) -> dict:
    """Parse + HMAC-verify a claim header value. Raises if the sig
    doesn't match. Returns the decoded k=v dict on success."""
    m = re.match(r"^(.*);sig=([0-9a-f]{64})$", value)
    assert m, f"claim has no ;sig=<hex>; got {value!r}"
    body, sig_hex = m.group(1), m.group(2)
    expected = hmac.new(SECRET, body.encode(), hashlib.sha256).hexdigest()
    assert hmac.compare_digest(expected, sig_hex), (
        f"sig mismatch: expected {expected}, got {sig_hex}"
    )
    out = {}
    for tok in body.split(";"):
        k, _, v = tok.partition("=")
        out[k] = v
    return out


# --- Default off -----------------------------------------------------


def test_no_claim_header_when_feature_off(config_override, fresh_ip):
    """Default: BotShieldAppClaims is off. No X-Botshield-Claims is
    set on the request, so the echo header carries the empty
    placeholder mod_headers emits when the source header is missing."""
    with config_override(
        r"BotShieldAllow\s+on",
        # No BotShieldAppClaims at all — feature stays off.
        'BotShieldAllow on\n'
        '    Header always set X-Echo-Claims "%{X-Botshield-Claims}i"',
        count=1,
    ):
        r = _g("/", xff=fresh_ip)
    echoed = r.headers.get("X-Botshield-Claims", "")
    # mod_headers writes the literal placeholder "(null)" or the
    # configured default-empty when the source request header is
    # absent. The exact placeholder varies; what we want is "no
    # actual claims body present". Anything containing 'sig=' would
    # be a real claim emission, which would mean the feature is
    # leaking when off.
    assert "sig=" not in echoed, (
        f"claims emitted when BotShieldAppClaims is off; "
        f"X-Echo-Claims={echoed!r}"
    )


# --- On: header emitted, sig verifies, fields populated -------------


def test_claim_header_emitted_and_signed(config_override, fresh_ip):
    """Feature on: every PASS-tier request gets a signed claim
    header. Body fields reflect the request's effective decision."""
    with config_override(
        r"BotShieldAllow\s+on", _cfg_on(), count=1,
    ):
        r = _g("/", xff=fresh_ip)
    claim = r.headers.get("X-Botshield-Claims")
    assert claim and "sig=" in claim, (
        f"no claim header on PASS-tier response; X-Echo-Claims={claim!r}"
    )
    parsed = _verify(claim)
    # Every advertised field is present.
    for k in ("v", "score", "tier", "cookie", "flags", "passes", "ts"):
        assert k in parsed, f"claim missing key '{k}'; parsed={parsed}"
    assert parsed["v"] == "1", parsed
    assert parsed["tier"] == "pass", parsed
    # Cookieless first-sight visit → cookie state is "absent".
    # `bs_decision_cookie_status` returns "absent" for the no-cookie
    # case; "missing" was an older internal name. Accept either to
    # keep this test resilient to the canonical spelling.
    assert parsed["cookie"] in ("absent", "missing"), parsed
    # passes counters are a fresh-cookie zero on this first request.
    assert parsed["passes"] == "s=0,f=0,c=0", parsed


# --- Strip-before-set: client-supplied X-Botshield-* sanitized ------


def test_client_supplied_x_botshield_headers_are_stripped(
    config_override, fresh_ip,
):
    """Attacker injects X-Botshield-Score: 0 and X-Botshield-Tier:
    pass to mislead a backend that doesn't verify the HMAC. The
    module strips all X-Botshield-* on read before setting its own
    claim header, so the attacker's values never reach the backend."""
    with config_override(
        r"BotShieldAllow\s+on", _cfg_on(), count=1,
    ):
        r = _g("/", xff=fresh_ip, headers={
            "X-Botshield-Score": "0",
            "X-Botshield-Tier":  "pass",
            "X-Botshield-Forged": "yes",
        })
    # `Header echo "X-Botshield-.*"` copies all matching request
    # headers into the response. After the strip + set sequence the
    # only X-Botshield-* surviving on the request side is our own
    # claim header — never the attacker's forged ones.
    assert r.headers.get("X-Botshield-Score") is None, (
        f"client-supplied X-Botshield-Score survived the strip"
    )
    assert r.headers.get("X-Botshield-Tier") is None, (
        f"client-supplied X-Botshield-Tier survived the strip"
    )
    assert r.headers.get("X-Botshield-Forged") is None, (
        f"client-supplied X-Botshield-Forged survived the strip"
    )
    # And the legitimate claim header still emitted (sig present).
    claim = r.headers.get("X-Botshield-Claims", "")
    assert "sig=" in claim, (
        f"strip discipline ran but module-set claims didn't: "
        f"X-Echo-Claims={claim!r}"
    )


# --- Tampering with the claim body breaks sig verification ----------


def test_tampered_claim_body_fails_app_side_verify(
    config_override, fresh_ip,
):
    """Sanity for the app-side verify step: any byte change in the
    body invalidates the HMAC. Not a module test per se — we forge
    locally and run the same verify step the app would. Catches
    accidental shape drift in our canonical-form serializer
    (whitespace, field ordering, value escaping, etc.)."""
    with config_override(
        r"BotShieldAllow\s+on", _cfg_on(), count=1,
    ):
        r = _g("/", xff=fresh_ip)
    claim = r.headers["X-Botshield-Claims"]
    # Flip the score value: change "score=N" to "score=999".
    tampered = re.sub(r"score=\d+", "score=999", claim, count=1)
    with pytest.raises(AssertionError):
        _verify(tampered)


# --- Feature on but secret file unset → claims not emitted ----------


def test_claims_not_emitted_without_secret(config_override, fresh_ip):
    """BotShieldAppClaims on without BotShieldAppIntegrationSecretFile
    is a misconfiguration. Module logs a warning at startup and skips
    the claim emit at request time rather than emitting an unsigned
    envelope or crashing the request. (Per-request fall-through is
    deliberate: the rest of the module — cookie tier, captcha,
    rate-limiting — should still work even when the operator has
    half-configured the optional app integration.)"""
    with config_override(
        r"BotShieldAllow\s+on",
        'BotShieldAllow on\n'
        '    BotShieldAppClaims on\n'
        # deliberately no SecretFile
        '    Header always set X-Echo-Claims "%{X-Botshield-Claims}i"',
        count=1,
    ):
        r = _g("/", xff=fresh_ip)
    claim = r.headers.get("X-Botshield-Claims", "")
    assert "sig=" not in claim, (
        f"claim emitted without a secret configured: {claim!r}"
    )
