# bash-legacy/

Archived bash test suite from M11.1–M11.3. Kept in-repo through
M11.5–M11.6 as a reference for reviewers and as a source for any
edge case the pytest port didn't pick up.

**Do not add new tests here.** The Python suite in `tests/pytests/`
+ `tests/botshield_test/` is the canonical framework going forward.
The bash scripts are no longer run by `tests/run`.

## Coverage map (bash → pytest)

| Bash script                             | Pytest test                                                                |
|-----------------------------------------|----------------------------------------------------------------------------|
| `unit/decision_format.sh`               | `pytests/test_decision_format.py`                                          |
| `integration/m2_cookie_hmac.sh`         | `pytests/test_cookie_hmac.py`                                              |
| `integration/m5_1_flagged_ip.sh`        | `pytests/test_flagged_ip.py`                                               |
| `integration/m5_2_bloom_first_sight.sh` | `pytests/test_bloom_first_sight.py`                                        |
| `integration/m6_state_round_trip.sh`    | `pytests/test_state_round_trip.py`                                         |
| `integration/m6_1_periodic_save.sh`     | `pytests/test_periodic_save.py`                                            |
| `integration/m7_silent_tier.sh`         | `pytests/test_silent_tier.py`                                              |
| `integration/m8_1_content_type.sh`      | `pytests/test_verify_content_type.py`                                      |
| `integration/m8_1_pending_cookie.sh`    | `pytests/test_verify_pending_cookie.py`                                    |
| `integration/m8_1_rate_limit.sh`        | `pytests/test_rate_limit.py`                                               |
| `integration/m8_captcha_turnstile.sh`    | `pytests/test_captcha_providers.py` (parametrized `turnstile`)            |
| `integration/m8_captcha_hcaptcha.sh`     | `pytests/test_captcha_providers.py` (parametrized `hcaptcha`)             |
| `integration/m8_captcha_recaptcha_v2.sh` | `pytests/test_captcha_providers.py` (parametrized `recaptcha_v2`)         |
| `integration/m8_captcha_recaptcha_v3.sh` | `pytests/test_captcha_providers.py` (parametrized `recaptcha_v3`)         |
| `integration/m8_captcha_friendly.sh`     | `pytests/test_captcha_providers.py` (parametrized `friendly`)             |
| `integration/m8_captcha_geetest.sh`      | `pytests/test_captcha_providers.py` (parametrized `geetest`)              |
| `integration/m9_1_enum_coverage.sh`     | `pytests/test_enum_coverage.py`                                            |
| `integration/m9_2_vocab_sync.sh`        | `pytests/test_vocab_sync.py`                                               |
| `integration/m9_3_metrics_parity.sh`    | `pytests/test_metrics_parity.py`                                           |
| `acceptance/pass_tier.sh`               | `pytests/test_acceptance_pass_tier.py`                                     |
| `acceptance/form_tier.sh`               | `pytests/test_acceptance_form_tier.py`                                     |
| `acceptance/captcha_tier.sh`            | `pytests/test_acceptance_captcha_tier.py`                                  |

The `lib/common.sh` helpers are replaced by the modules under
`botshield_test/`; `lib/decision_gate.awk` is replaced by
`botshield_test.logs.validate_decision`. `solve_pow.py` folded into
`botshield_test.cookies.solve_pow`.

## When to delete

Proposed: delete `tests/bash-legacy/` at the end of M11.7 once the
pytest suite has run green in CI for a week and the Playwright
acceptance layer (M11.6) is in.
