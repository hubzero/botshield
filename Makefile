# Build and install mod_botshield via apxs.
#
#   make            build only
#   make install    build + install the .so into Apache's modules dir
#   make enable     install + a2enmod + configtest + reload
#   make disable    a2dismod + reload (leaves .so in place)
#   make reload     configtest + reload (no rebuild)
#   make clean      remove build artifacts
#
# M10.1 sanitizer targets:
#   make sanitize        build with ASan + UBSan + frame pointers + -g
#   make install-sanitize  install the sanitized .so (requires Apache
#                          started under LD_PRELOAD; see
#                          apache/botshield-sanitize.env)

APXS     ?= apxs
MOD_NAME ?= botshield
SRC      := src/mod_$(MOD_NAME).c
LA       := $(SRC:.c=.la)

# Pass warnings through apxs to the underlying compiler.
CFLAGS_WARN := -Wc,-Wall -Wc,-Wextra -Wc,-Wno-unused-parameter

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

.PHONY: all build install enable disable reload clean \
        sanitize install-sanitize

all: build

build:
	$(APXS) -c $(CFLAGS_WARN) $(SRC) $(LIBS)

install: build
	sudo $(APXS) -i -n $(MOD_NAME) $(LA)

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

# --- M10.1 ---

sanitize: clean
	$(APXS) -c $(CFLAGS_WARN) $(CFLAGS_SAN) $(SRC) $(LIBS)

install-sanitize: sanitize
	sudo $(APXS) -i -n $(MOD_NAME) $(LA)
