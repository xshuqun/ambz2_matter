all: is

OS := $(shell uname)
LBITS := $(shell getconf LONG_BIT)

include toolchain.mk

.PHONY: is
is: toolchain
	cp partition_default.json partition.json
	@$(MAKE) -f application.is.mk

.PHONY: tz
tz: toolchain
	@$(MAKE) -f application.tz.mk

.PHONY: mp
mp: toolchain
	@$(MAKE) -f application.is.mk mp

.PHONY: clean
clean:
	@$(MAKE) -f application.is.mk clean

.PHONY: is_matter
is_matter: toolchain
	cp partition_matter.json partition.json
	@$(MAKE) -f application.is.matter.mk


.PHONY: clean_matter
clean_matter:
	@$(MAKE) -f application.is.matter.mk clean

debug: toolchain
	@$(MAKE) -f application.is.mk debug

debug_tz: toolchain
	@$(MAKE) -f application.tz.mk debug

flash: toolchain
	@$(MAKE) -f application.is.mk flash

flash_tz: toolchain
	@$(MAKE) -f application.tz.mk flash
	
setup:
	@$(MAKE) -f application.is.mk $(MAKECMDGOALS)	

setup_tz:
	@$(MAKE) -f application.tz.mk $(MAKECMDGOALS)
