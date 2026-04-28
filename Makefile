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
DOCS_PYTHON ?= python3
DOCS_BUILD  := tools/build_site.py
# Keep botshield.c first — apxs derives the .la/.so name from the
# first source. Extra .c files are compiled into the same shared
# object and share the module's pool/APR linkage. The installed .so
# is named mod_botshield.so via apxs's -n flag at install time, which
# is what Apache's LoadModule directive references; the source file
# stays bare-named to match the rest of src/.
MAIN_SRC := src/$(MOD_NAME).c
EXTRA_SRC := src/robots.c src/shm.c src/crypto.c src/allowlist.c src/metrics.c src/challenge.c src/cookie.c src/silent.c src/captcha.c src/bridge.c
SRC      := $(MAIN_SRC) $(EXTRA_SRC)
LA       := $(MAIN_SRC:.c=.la)

# Pass warnings through apxs to the underlying compiler.
CFLAGS_WARN := -Wc,-Wall -Wc,-Wextra -Wc,-Wno-unused-parameter

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

.PHONY: all build install enable disable reload clean docs \
        sanitize install-sanitize \
        fuzz fuzz-run fuzz-clean \
        fuzz-robots fuzz-robots-run

all: build

build:
	$(APXS) -c $(CFLAGS_WARN) $(CFLAGS_VIS) $(SRC) $(LIBS)

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

docs:
	$(DOCS_PYTHON) $(DOCS_BUILD)

# --- M10.1 ---

sanitize: clean
	$(APXS) -c $(CFLAGS_WARN) $(CFLAGS_VIS) $(CFLAGS_SAN) $(SRC) $(LIBS)

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
