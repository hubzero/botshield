#!/bin/bash
# integration/m9_3_metrics_parity — for every enum value across tier /
# outcome / cookie / provider, assert delta(/metrics) equals the count
# of decision-log lines carrying that enum. M9.3's core contract:
# counters never drift from the log vocabulary.
set -u
source "$(dirname "$0")/../lib/common.sh"

before=$(metrics_snapshot)
mark=$(log_mark)

# Drive a controlled mix so we hit several enum values.
for i in 1 2 3 4 5; do
  bs_curl -o /dev/null \
    -A "Mozilla/5.0 (X11) Chrome/145" -H "Accept-Language: en-US" \
    -H "X-Forwarded-For: 203.0.113.$((160+i))" "$BASE/" > /dev/null
done
for i in 1 2 3; do
  bs_curl -o /dev/null -A "python-requests/2.31" \
    -H "X-Forwarded-For: 203.0.113.$((170+i))" "$BASE/" > /dev/null
done
for i in 1 2; do
  bs_curl -o /dev/null "$BASE/captcha-demo" > /dev/null
done

# pending_missing
bs_curl -o /dev/null -X POST \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "cf-turnstile-response=x" \
  "$BASE/botshield/captcha-verify/turnstile" > /dev/null

after=$(metrics_snapshot)
slice=$(log_slice "$mark")

# Walk every dimension, assert delta == count.
drift=0
for prefix in tier outcome cookie; do
  case "$prefix" in
    tier)    enums="$TIERS"    ;;
    outcome) enums="$OUTCOMES" ;;
    cookie)  enums="$COOKIES"  ;;
  esac
  for e in $enums; do
    metric="botshield_${prefix}_${e}_total"
    delta=$(metrics_delta "$before" "$after" "$metric")
    log_count=$(grep -c "mod_botshield: decision .*${prefix}=${e} " "$slice" || true)
    if [[ "$delta" != "$log_count" ]]; then
      echo "  DRIFT: $metric delta=$delta log=$log_count"
      drift=1
    fi
  done
done

# Provider enum: metric name uses underscores, log uses hyphens.
for e in $PROVIDERS; do
  log_e="${e//_/-}"
  metric="botshield_provider_${e}_total"
  delta=$(metrics_delta "$before" "$after" "$metric")
  log_count=$(grep -c "mod_botshield: decision .*provider=${log_e} " "$slice" || true)
  if [[ "$delta" != "$log_count" ]]; then
    echo "  DRIFT: $metric delta=$delta log=$log_count"
    drift=1
  fi
done

rm -f "$before" "$after" "$slice"

if [[ "$drift" != "0" ]]; then
  t_fail "counter/log drift on at least one enum value"
fi
t_pass "all 26 counter dimensions match decision log"
