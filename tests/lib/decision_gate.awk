#!/usr/bin/awk -f
#
# M9a decision-log validator. Reads lines from Apache error.log,
# picks the botshield "decision" entries, splits them into key=value
# pairs, and asserts:
#   - every required key is present
#   - tier/outcome/cookie values are from their documented enums
#   - provider is either "-" or a known name
#   - score is an integer
#
# Any line that fails is printed to stderr prefixed with "BAD:".
# Exit code 0 = all lines parsed cleanly, 1 = at least one failure.

BEGIN {
    split("none pass silent form captcha",   tiers,    " ")
    split("declined challenged verified rejected failopen rate_limited " \
          "inflight_capped pending_missing misconfigured debug",
          outcomes, " ")
    split("ok expired bad_sig bad_format absent -",  cookies,  " ")
    split("- turnstile hcaptcha recaptcha-v2 recaptcha-v3 friendly geetest",
          providers, " ")
    for (k in tiers)     enum_tier[tiers[k]]     = 1
    for (k in outcomes)  enum_outcome[outcomes[k]] = 1
    for (k in cookies)   enum_cookie[cookies[k]]   = 1
    for (k in providers) enum_provider[providers[k]] = 1

    required[1] = "tier"
    required[2] = "outcome"
    required[3] = "ip"
    required[4] = "score"
    required[5] = "cookie"
    required[6] = "provider"
    required[7] = "alg"
    required[8] = "reason"
    required[9] = "path"

    total   = 0
    failed  = 0
}

# Match the "decision " marker after any Apache prefix.
/mod_botshield: decision / {
    total++
    line = $0
    # Strip everything up to and including "decision "
    sub(/^.*mod_botshield: decision /, "", line)
    # Parse key=value pairs. Values can be double-quoted.
    delete kv
    rest = line
    while (length(rest) > 0) {
        # Skip leading whitespace.
        sub(/^[[:space:]]+/, "", rest)
        if (length(rest) == 0) break
        # Key is [a-z_]+ up to =.
        if (match(rest, /^[a-z_]+=/) == 0) break
        key = substr(rest, 1, RLENGTH - 1)
        rest = substr(rest, RLENGTH + 1)
        if (substr(rest, 1, 1) == "\"") {
            # Quoted value: read until unescaped close quote.
            rest = substr(rest, 2)
            val = ""
            while (length(rest) > 0) {
                c = substr(rest, 1, 1)
                if (c == "\\" && length(rest) > 1) {
                    val = val substr(rest, 2, 1)
                    rest = substr(rest, 3)
                } else if (c == "\"") {
                    rest = substr(rest, 2)
                    break
                } else {
                    val = val c
                    rest = substr(rest, 2)
                }
            }
        } else {
            # Unquoted: read until whitespace.
            if (match(rest, /[[:space:]]/)) {
                val = substr(rest, 1, RSTART - 1)
                rest = substr(rest, RSTART)
            } else {
                val = rest
                rest = ""
            }
        }
        kv[key] = val
    }

    bad = 0
    for (i = 1; i <= 9; i++) {
        if (!(required[i] in kv)) {
            print "BAD: missing key " required[i] " in: " $0 > "/dev/stderr"
            bad = 1
        }
    }
    if (!(kv["tier"] in enum_tier)) {
        print "BAD: tier=" kv["tier"] " not in enum in: " $0 > "/dev/stderr"
        bad = 1
    }
    if (!(kv["outcome"] in enum_outcome)) {
        print "BAD: outcome=" kv["outcome"] " not in enum in: " $0 > "/dev/stderr"
        bad = 1
    }
    if (!(kv["cookie"] in enum_cookie)) {
        print "BAD: cookie=" kv["cookie"] " not in enum in: " $0 > "/dev/stderr"
        bad = 1
    }
    if (!(kv["provider"] in enum_provider)) {
        print "BAD: provider=" kv["provider"] " not in enum in: " $0 > "/dev/stderr"
        bad = 1
    }
    if (kv["score"] !~ /^-?[0-9]+$/) {
        print "BAD: score=" kv["score"] " not integer in: " $0 > "/dev/stderr"
        bad = 1
    }
    if (bad) failed++
}

END {
    printf "decision lines: %d parsed, %d failed\n", total, failed
    exit (failed > 0 ? 1 : 0)
}
