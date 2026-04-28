/*
 * tests/fuzz/_fuzz_stubs.h — #included before botshield.c inside
 * the fuzz harness.
 *
 * Responsibilities:
 *   1. Define BS_FUZZ_HARNESS so the production source gates out the
 *      module declaration (AP_DECLARE_MODULE) and bs_register_hooks
 *      — both of which reference Apache symbols the fuzz binary
 *      doesn't link against.
 *   2. Neuter the APLOG logging macros at the outer-variadic level
 *      so argument splitting doesn't trip over APLOG_MARK's three-
 *      token expansion.
 *
 * That's it. We don't stub ap_hook_*, ap_get_module_config, etc. —
 * by gating bs_register_hooks and AP_DECLARE_MODULE, the fuzz
 * translation unit never references them.
 */
#ifndef BS_FUZZ_STUBS_H
#define BS_FUZZ_STUBS_H

#define BS_FUZZ_HARNESS 1

#include <httpd.h>
#include <http_config.h>
#include <http_log.h>
#include <http_protocol.h>
#include <apr_strings.h>
#include <apr_base64.h>
#include <apr_time.h>

/* Silence the log macros. Swallow everything at the outer level —
 * Apache's real macros use a variadic trampoline to force APLOG_MARK
 * to expand before argument splitting; we take the same precaution
 * by accepting any arg shape. */
#undef  ap_log_rerror
#define ap_log_rerror(...) do { } while (0)

#undef  ap_log_error
#define ap_log_error(...)  do { } while (0)

#endif /* BS_FUZZ_STUBS_H */
