all: is

OS := $(shell uname)
LBITS := $(shell getconf LONG_BIT)

.PHONY: toolchain
toolchain:
ifeq ($(findstring Linux, $(OS)), Linux)
ifneq ("$(LBITS)", "64")
	@echo ONLY 64-BIT LINUX IS SUPPORTED!
	@exit -1
endif
	if [ ! -f ../../../tools/arm-none-eabi-gcc/asdk-10.3.0-linux-newlib-build-3638-x86_64.tar.bz2 ] ; then cat ../../../tools/arm-none-eabi-gcc/asdk-10.3.0-linux-newlib-build-3638-x86_64.tar.bz2* > ../../../tools/arm-none-eabi-gcc/asdk-10.3.0-linux-newlib-build-3638-x86_64.tar.bz2; fi;\
	if [ ! -d ../../../tools/arm-none-eabi-gcc/asdk ] ; then mkdir ../../../tools/arm-none-eabi-gcc/asdk; fi;\
	if [ ! -d ../../../tools/arm-none-eabi-gcc/asdk/linux ] ; then tar -jxf ../../../tools/arm-none-eabi-gcc/asdk-10.3.0-linux-newlib-build-3638-x86_64.tar.bz2 -C ../../../tools/arm-none-eabi-gcc/ ; mv ../../../tools/arm-none-eabi-gcc/asdk-10.3.0/linux ../../../tools/arm-none-eabi-gcc/asdk/linux ; rmdir ../../../tools/arm-none-eabi-gcc/asdk-10.3.0; fi
endif
	@echo Toolchain unzip done!

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
