# Build and install mod_botshield via apxs.
#
#   make            build only
#   make install    build + install the .so into Apache's modules dir
#   make enable     install + a2enmod + configtest + reload
#   make disable    a2dismod + reload (leaves .so in place)
#   make reload     configtest + reload (no rebuild)
#   make clean      remove build artifacts

APXS     ?= apxs
MOD_NAME ?= botshield
SRC      := src/mod_$(MOD_NAME).c
LA       := $(SRC:.c=.la)

# Pass warnings through apxs to the underlying compiler.
CFLAGS_WARN := -Wc,-Wall -Wc,-Wextra -Wc,-Wno-unused-parameter

.PHONY: all build install enable disable reload clean

all: build

build:
	$(APXS) -c $(CFLAGS_WARN) $(SRC)

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
