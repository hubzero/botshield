# Build and install mod_botshield via apxs.
#
#   make            build only
#   make install    build + install the .so into Apache's modules dir
#   make enable     install + a2enmod + configtest + reload
#   make disable    a2dismod + reload (leaves .so in place)
#   make reload     configtest + reload (no rebuild)
#   make clean      remove build artifacts
#   make docs       build the static project site into ./docs
#
# M10.1 sanitizer targets:
#   make sanitize        build with ASan + UBSan + frame pointers + -g
#   make install-sanitize  install the sanitized .so (requires Apache
#                          started under LD_PRELOAD; see
#                          apache/botshield-sanitize.env)

APXS     ?= apxs
MOD_NAME ?= botshield
# build_site.py needs 3.7+ (it uses `from __future__ import
# annotations`) and markdown-it-py. RHEL 8 ships 3.6 as plain
# `python3`, and a newer interpreter on PATH is not necessarily the
# one the docs deps were installed into -- so probe for an
# interpreter that can actually import markdown_it, and only fall
# back to a version check when none can (so the build still reaches
# build_site.py's own install hint instead of dying on a
# SyntaxError). Override DOCS_PYTHON to force one.
# The repo's own test venv comes first: it is the one interpreter in
# this tree whose dependencies are managed, and `make docs` had simply
# been failing on hosts where no system python carries markdown-it-py
# (the whole target was dead here until someone tried to run it). Look
# there before the system interpreters so a developer who has set up
# the test venv gets a working docs build without a second install
# step. `make docs-deps` populates it.
DOCS_PY_CANDIDATES := tests/.venv/bin/python \
	python3 python3.12 python3.11 python3.10 \
	python3.9 python3.8
DOCS_PYTHON ?= $(shell \
	for py in $(DOCS_PY_CANDIDATES); do \
		command -v $$py >/dev/null 2>&1 || continue; \
		if $$py -c 'import markdown_it' 2>/dev/null; then \
			echo $$py; exit 0; fi; \
	done; \
	for py in $(DOCS_PY_CANDIDATES); do \
		command -v $$py >/dev/null 2>&1 || continue; \
		if $$py -c 'import sys; sys.exit(sys.version_info < (3,7))' \
		   2>/dev/null; then echo $$py; exit 0; fi; \
	done; echo python3)
DOCS_BUILD  := gh-pages/build_site.py
# Keep botshield.c first — apxs derives the .la/.so name from the
# first source. Extra .c files are compiled into the same shared
# object and share the module's pool/APR linkage. The installed .so
# is named mod_botshield.so via apxs's -n flag at install time, which
# is what Apache's LoadModule directive references; the source file
# stays bare-named to match the rest of src/.
MAIN_SRC := src/$(MOD_NAME).c
EXTRA_SRC := src/robots.c src/shm.c src/crypto.c src/allowlist.c src/generated_verified_bots.c src/metrics.c src/challenge.c src/cookie.c src/load.c src/triggers.c src/config.c src/templates.c src/formcaptcha.c src/score.c src/policy.c src/heuristics.c src/non_interactive.c src/captcha.c src/bridge.c src/bot_directory.c src/generated_bot_directory.c src/browser_classifier.c src/generated_browser_templates.c src/ua_class.c src/bot_rate.c
SRC      := $(MAIN_SRC) $(EXTRA_SRC)
LA       := $(MAIN_SRC:.c=.la)

# generated_bot_directory.c is regenerated from the vendored JSON.
# Codegen runs whenever the JSON's mtime is newer than the .c.
# Operators refresh the JSON via tools/refresh-bot-directory.py
# (network fetch + validation + atomic replace); we never auto-run
# refresh from the build, only codegen.
GEN_BOT_DIR_C    := src/generated_bot_directory.c
GEN_BOT_DIR_JSON := vendor/bot-directory.json
GEN_BOT_DIR_TOOL := tools/gen-bot-directory.py
# The generator also reads the .builtin (committed) and .local
# (gitignored) overlays. They have to be prerequisites too, or editing
# one leaves a stale .c behind with no error and no output -- the
# build succeeds and silently ships the previous data. wildcard so a
# missing .local is simply no prerequisite rather than a hard failure.
GEN_BOT_DIR_OVERLAYS := $(wildcard vendor/bot-directory.builtin.json \
                                   vendor/bot-directory.local.json)

$(GEN_BOT_DIR_C): $(GEN_BOT_DIR_JSON) $(GEN_BOT_DIR_OVERLAYS) $(GEN_BOT_DIR_TOOL)
	$(DOCS_PYTHON) $(GEN_BOT_DIR_TOOL)

# Browser-templates codegen — same shape as bot-directory.
GEN_BROWSER_C    := src/generated_browser_templates.c
GEN_BROWSER_JSON := vendor/top-user-agents.json
GEN_BROWSER_TOOL := tools/gen-browser-templates.py
GEN_BROWSER_OVERLAYS := $(wildcard vendor/top-user-agents.builtin.json \
                                   vendor/top-user-agents.local.json)

$(GEN_BROWSER_C): $(GEN_BROWSER_JSON) $(GEN_BROWSER_OVERLAYS) $(GEN_BROWSER_TOOL)
	$(DOCS_PYTHON) $(GEN_BROWSER_TOOL)

# Verified-bot built-ins codegen — bs_builtin_bots[] used to be a
# hardcoded C array; now codegenned from a vendor JSON for symmetry
# with the other two data sources. No external upstream, so the
# .json IS the project's curated set (no .builtin layer); operator
# overlay at vendor/verified-bots.local.json (gitignored).
GEN_VBOTS_C    := src/generated_verified_bots.c
GEN_VBOTS_JSON := vendor/verified-bots.json
GEN_VBOTS_TOOL := tools/gen-verified-bots.py
GEN_VBOTS_OVERLAYS := $(wildcard vendor/verified-bots.local.json)

$(GEN_VBOTS_C): $(GEN_VBOTS_JSON) $(GEN_VBOTS_OVERLAYS) $(GEN_VBOTS_TOOL)
	$(DOCS_PYTHON) $(GEN_VBOTS_TOOL)

# Pass warnings through apxs to the underlying compiler.
CFLAGS_WARN := -Wc,-Wall -Wc,-Wextra -Wc,-Wno-unused-parameter

# Where rotatelogs lives, asked of the same apxs that builds us rather
# than hardcoded. The module uses it to build a rotating decision-log
# default; if the binary is absent at runtime the default falls back to
# a plain file, so a wrong answer here degrades rather than breaks.
APXS_SBINDIR := $(shell $(APXS) -q SBINDIR 2>/dev/null)
CFLAGS_ROTATELOGS := -Wc,-DBS_ROTATELOGS_PATH='\"$(APXS_SBINDIR)/rotatelogs\"'

# Hide cross-file bs_* symbols from the dynamic-linker symbol table.
# Apache modules share the parent httpd's dynamic symbol space; without
# this, two modules with same-named non-static functions could resolve
# to whichever loaded first. The module entry point (botshield_module)
# stays default-visible via a #pragma GCC visibility push/pop in
# botshield.c — Apache's LoadModule resolves it via dlsym.
CFLAGS_VIS := -Wc,-fvisibility=hidden

# Sanitizer flags for the M10.1 pass. -Wc,... forwards compiler flags
# through apxs; -Wl,... forwards linker flags. Frame pointers on so
# ASan's stack traces are actually readable. -O1 instead of -O2 to
# keep inlining bounded without disabling optimization entirely (so
# bugs that only show up with optimization still show up here).
#
# -fno-sanitize=object-size is deliberate: __builtin_object_size can't
# see through APR pool allocation (chunks are bulk-malloced, individual
# apr_palloc slices are sub-allocations the compiler doesn't track), so
# this check produces spurious "insufficient space" reports on any
# pool-returned string. The rest of UBSan's checks (null pointer deref,
# signed overflow, array bounds on arrays the compiler CAN see, shift
# overflow, alignment, bool/enum-load, etc.) still fire normally.
CFLAGS_SAN := \
	-Wc,-fsanitize=address \
	-Wc,-fsanitize=undefined -Wc,-fno-sanitize=object-size \
	-Wc,-fno-omit-frame-pointer -Wc,-g -Wc,-O1 \
	-Wl,-fsanitize=address -Wl,-fsanitize=undefined

# Link against OpenSSL for HMAC + SHA + RAND, libcurl for captcha
# provider siteverify calls (M8), and json-c for parsing the siteverify
# response. apxs forwards trailing -l args to the linker.
LIBS := -lcrypto -lcurl -ljson-c

.PHONY: all build install enable disable reload clean test-clean docs docs-deps \
        toolchain-fix \
        sanitize install-sanitize \
        fuzz fuzz-run fuzz-clean \
        fuzz-robots fuzz-robots-run

all: build

build: $(GEN_BOT_DIR_C) $(GEN_BROWSER_C) $(GEN_VBOTS_C)
	$(APXS) -c $(CFLAGS_WARN) $(CFLAGS_ROTATELOGS) $(CFLAGS_VIS) $(SRC) $(LIBS)

install: build
	@# apxs -i derives the installed .so name from the .la basename,
	@# so a bare-named botshield.c source would install as
	@# botshield.so — but Apache's LoadModule directive references
	@# the conventional mod_<name>.so. Install manually to keep the
	@# operator-visible name correct.
	sudo install -m 644 src/.libs/$(MOD_NAME).so \
	    $(shell $(APXS) -q LIBEXECDIR)/mod_$(MOD_NAME).so

enable: install
	@printf 'LoadModule %s_module /usr/lib/apache2/modules/mod_%s.so\n' \
	    $(MOD_NAME) $(MOD_NAME) | \
	    sudo tee /etc/apache2/mods-available/$(MOD_NAME).load >/dev/null
	sudo a2enmod $(MOD_NAME)
	sudo apachectl configtest
	sudo systemctl reload apache2

disable:
	sudo a2dismod $(MOD_NAME) || true
	sudo systemctl reload apache2

reload:
	sudo apachectl configtest
	sudo systemctl reload apache2

clean:
	rm -rf src/.libs src/*.lo src/*.la src/*.slo src/*.o

# Transient pytest / __pycache__ / report artifacts. Spares two
# things on purpose:
#   - tests/.venv: expensive to recreate (pip install of pytest +
#     plugins). Wipe with `rm -rf tests/.venv` if you actually want
#     to start over.
#   - .hypothesis/examples/: Hypothesis's saved-failure database.
#     Each entry is a minimized counter-example that gets replayed
#     on every run, guarding against regression of a property test
#     that already failed once. Throwing it away on every clean
#     erases that protection. Use `git clean -fdx` if you really
#     want a pristine tree.
#
# Also wipes .playwright-mcp/ — DOM snapshots and console logs
# from past Playwright MCP sessions. No replay value; safe to
# nuke any time.
test-clean:
	@# Anchor check + absolute paths via $(CURDIR). The two
	@# defenses against an `rm -rf` that ran from the wrong place:
	@# (a) refuse if this directory doesn't look like the repo;
	@# (b) use $(CURDIR) so a misbehaving sub-shell `cd` can't move
	@# the deletion target out from under the rule.
	@test -f "$(CURDIR)/src/botshield.c" || { \
	  echo "test-clean: $(CURDIR) doesn't look like the mod_botshield repo; refusing." >&2; \
	  exit 1; \
	}
	rm -rf "$(CURDIR)/tests/reports" \
	       "$(CURDIR)/tests/test-results" \
	       "$(CURDIR)/.playwright-mcp"
	find "$(CURDIR)" -type d \( -name .pytest_cache -o -name __pycache__ \) \
	     -prune -exec rm -rf {} +

docs:
	$(DOCS_PYTHON) $(DOCS_BUILD)

# Install the docs toolchain into the test venv, which is where
# DOCS_PY_CANDIDATES looks first. Separate target rather than a
# prerequisite of `docs` so a build never reaches out to the network
# on its own.
# Host hardening on this box periodically resets the compiler and
# assembler to mode 754, which breaks the build with a bare
# "/usr/bin/gcc: Permission denied" from libtool -- a message that
# points at the toolchain rather than at the policy that changed it.
# This restores the mode so the next build works.
#
# Note /usr/bin/ld needs nothing: it is a symlink, and symlink bits are
# always lrwxrwxrwx on Linux and ignored by the kernel. Access is
# governed by the target (/usr/bin/ld.bfd, 755). Reading the link's
# bits as the binary's is an easy way to invent a finding that is not
# there.
toolchain-fix:
	@for t in /usr/bin/gcc /usr/bin/as; do \
		m=$$(stat -c '%a' $$t); \
		if [ "$$m" != "755" ]; then \
			echo "$$t is $$m -> restoring 755"; \
			sudo chmod 755 $$t; \
		else echo "$$t already 755"; fi; \
	done

docs-deps:
	@test -x tests/.venv/bin/pip || { \
		echo "tests/.venv not found - create it first (see tests/README)"; \
		exit 1; }
	tests/.venv/bin/pip install -r gh-pages/requirements.txt

# --- M10.1 ---

sanitize: clean
	$(APXS) -c $(CFLAGS_WARN) $(CFLAGS_ROTATELOGS) $(CFLAGS_VIS) $(CFLAGS_SAN) $(SRC) $(LIBS)

install-sanitize: sanitize
	sudo install -m 644 src/.libs/$(MOD_NAME).so \
	    $(shell $(APXS) -q LIBEXECDIR)/mod_$(MOD_NAME).so

# --- M11.8 fuzz ---
#
# LibFuzzer harness for bs_verify_cookie. Builds with clang +
# -fsanitize=fuzzer,address,undefined. Requires:
#   apt install clang libfuzzer-<version>-dev
# The harness #includes src/botshield.c directly; _fuzz_stubs.h
# provides weak stubs for Apache runtime symbols the fuzzer never
# reaches (see the header for the approach).

FUZZ_CC    ?= clang
FUZZ_BIN   := tests/fuzz/fuzz_cookie
FUZZ_SRC   := tests/fuzz/fuzz_cookie.c
FUZZ_STUBS := tests/fuzz/_fuzz_stubs.h

# apxs flags for apr/apache headers — clang can't find them without these.
FUZZ_CPPFLAGS := $(shell $(APXS) -q INCLUDEDIR 2>/dev/null) \
                 $(shell pkg-config --cflags apr-1 apr-util-1 2>/dev/null)
FUZZ_CPPFLAGS := -I$(shell $(APXS) -q INCLUDEDIR) \
                 $(shell pkg-config --cflags apr-1 apr-util-1)

FUZZ_LIBS := -lcrypto -lcurl -ljson-c \
             $(shell pkg-config --libs apr-1 apr-util-1) \
             -lpcre2-8

FUZZ_CFLAGS := -g -O1 -fno-omit-frame-pointer \
               -fsanitize=fuzzer,address,undefined \
               -fno-sanitize=object-size \
               -Wno-deprecated-declarations

fuzz: $(FUZZ_BIN)

$(FUZZ_BIN): $(FUZZ_SRC) $(FUZZ_STUBS) $(SRC)
	$(FUZZ_CC) $(FUZZ_CFLAGS) $(FUZZ_CPPFLAGS) \
	    -o $@ $(FUZZ_SRC) $(FUZZ_LIBS)

# tests/fuzz/run.sh calls this. Default runtime is a short smoke —
# for a real campaign, pass a longer value: `make fuzz-run DURATION=300`
DURATION ?= 30
# Security review MEDIUM #15 — explicit per-input timeout and memory
# cap. Without these, LibFuzzer defaults are 1200s per-input and
# 2048 MB RSS — slow-unit findings would surface as "CI step
# timeout" rather than as a slow-unit-<hash> reproducer file.
# 10s per-input and 512 MB RSS are well above any legitimate run
# of these targets (which complete each input in microseconds and
# never grow past ~30 MB) but tight enough that real findings
# trip the limit and produce reproducers.
FUZZ_TIMEOUT_S    ?= 10
FUZZ_RSS_LIMIT_MB ?= 512

fuzz-run: fuzz
	$(FUZZ_BIN) -max_total_time=$(DURATION) \
	    -timeout=$(FUZZ_TIMEOUT_S) \
	    -rss_limit_mb=$(FUZZ_RSS_LIMIT_MB) \
	    -print_final_stats=1 \
	    tests/fuzz/corpus

# --- E2.2.3 robots.txt fuzz ---
#
# Second LibFuzzer harness, targeting src/robots.c. Independent from
# fuzz_cookie — robots.c is APR-only, no httpd dependency, so no
# stubs are needed and the build command is shorter.

FUZZ_ROBOTS_BIN := tests/fuzz/fuzz_robots
FUZZ_ROBOTS_SRC := tests/fuzz/fuzz_robots.c

fuzz-robots: $(FUZZ_ROBOTS_BIN)

$(FUZZ_ROBOTS_BIN): $(FUZZ_ROBOTS_SRC) src/robots.c src/robots.h
	$(FUZZ_CC) $(FUZZ_CFLAGS) $(FUZZ_CPPFLAGS) \
	    -o $@ $(FUZZ_ROBOTS_SRC) \
	    $(shell pkg-config --libs apr-1)

fuzz-robots-run: fuzz-robots
	@mkdir -p tests/fuzz/corpus-robots
	@if [ -z "$$(ls -A tests/fuzz/corpus-robots 2>/dev/null)" ]; then \
	    cp tests/fuzz/seeds-robots/* tests/fuzz/corpus-robots/ ; \
	fi
	$(FUZZ_ROBOTS_BIN) -max_total_time=$(DURATION) \
	    -timeout=$(FUZZ_TIMEOUT_S) \
	    -rss_limit_mb=$(FUZZ_RSS_LIMIT_MB) \
	    -print_final_stats=1 \
	    tests/fuzz/corpus-robots

fuzz-clean:
	rm -f $(FUZZ_BIN) $(FUZZ_ROBOTS_BIN)
