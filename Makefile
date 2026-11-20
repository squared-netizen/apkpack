# apkpack: make, make test, make clean.
#
# Needs clang and libc++ with `import std;` (23, the SDK's toolchain):
#
#   make CXX=/path/to/clang++
#
# Offline: micro-ecc is vendored in third_party/micro-ecc, and the std
# module is built here from the libc++ the compiler uses.

CXX      ?= clang++
CC       ?= clang
BUILD    ?= build
OPT      ?= -O2 -g
STDLIB   := -stdlib=libc++
WARN     := -Wall -Wextra -Wpedantic -Wconversion -Wno-sign-conversion -Wno-missing-field-initializers
CXXFLAGS := -std=c++23 $(STDLIB) $(OPT) $(WARN) -fprebuilt-module-path=$(BUILD)/pcm -fmodule-file=std=$(BUILD)/pcm/std.pcm
UECC     := -DuECC_SUPPORTS_secp160r1=0 -DuECC_SUPPORTS_secp192r1=0 -DuECC_SUPPORTS_secp224r1=0 \
            -DuECC_SUPPORTS_secp256r1=1 -DuECC_SUPPORTS_secp256k1=0
CFLAGS   := $(OPT) $(UECC)
LDFLAGS  := $(STDLIB)

STD_MANIFEST := $(shell readlink -f "$$($(CXX) $(STDLIB) -print-library-module-manifest-path 2>/dev/null)" 2>/dev/null)
STD_SOURCE   := $(if $(STD_MANIFEST),$(shell sed -n 's/.*"source-path": *"\([^"]*std\.cppm\)".*/\1/p' $(STD_MANIFEST) 2>/dev/null | head -n 1))
STD_CPPM     ?= $(if $(filter /%,$(STD_SOURCE)),$(STD_SOURCE),$(if $(STD_SOURCE),$(dir $(STD_MANIFEST))$(STD_SOURCE)))

MODULES := crypto der apk zip res link
OBJS    := $(BUILD)/obj/std.o $(BUILD)/obj/uECC.o $(MODULES:%=$(BUILD)/obj/%.o)
TESTS   := $(patsubst tests/%.cpp,$(BUILD)/%,$(wildcard tests/test_*.cpp))

.PHONY: all test clean
all: $(BUILD)/apkpack $(TESTS)

$(BUILD)/pcm/std.pcm:
	@test -n "$(STD_CPPM)" && test -f "$(STD_CPPM)" || { echo "no libc++ std module (set STD_CPPM)" >&2; exit 1; }
	@mkdir -p $(BUILD)/pcm $(BUILD)/obj
	$(CXX) -std=c++23 $(STDLIB) $(OPT) -Wno-reserved-module-identifier --precompile $(STD_CPPM) -o $@
$(BUILD)/obj/std.o: $(BUILD)/pcm/std.pcm
	$(CXX) $(OPT) -c $< -o $@

$(BUILD)/obj/uECC.o: third_party/micro-ecc/uECC.c
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -c $< -o $@

# A module: its BMI and its object.
define unit
$(BUILD)/pcm/apkpack.$(1).pcm $(BUILD)/obj/$(1).o &: src/$(1).cppm $(BUILD)/pcm/std.pcm $(2)
	@mkdir -p $(BUILD)/pcm $(BUILD)/obj
	$(CXX) $(CXXFLAGS) $(UECC) -Ithird_party/micro-ecc -Isrc -c $$< -fmodule-output=$(BUILD)/pcm/apkpack.$(1).pcm -o $(BUILD)/obj/$(1).o
endef
$(eval $(call unit,crypto,))
$(eval $(call unit,der,$(BUILD)/pcm/apkpack.crypto.pcm))
$(eval $(call unit,apk,$(BUILD)/pcm/apkpack.crypto.pcm $(BUILD)/pcm/apkpack.der.pcm))
$(eval $(call unit,zip,$(BUILD)/pcm/apkpack.crypto.pcm))
$(eval $(call unit,res,$(BUILD)/pcm/apkpack.crypto.pcm src/android_table.inc))
$(eval $(call unit,link,$(BUILD)/pcm/apkpack.crypto.pcm $(BUILD)/pcm/apkpack.res.pcm $(BUILD)/pcm/apkpack.zip.pcm))

$(BUILD)/apkpack: tools/apkpack.cpp $(OBJS)
	$(CXX) $(CXXFLAGS) $< $(OBJS) $(LDFLAGS) -o $@

$(BUILD)/test_%: tests/test_%.cpp $(OBJS)
	$(CXX) $(CXXFLAGS) $< $(OBJS) $(LDFLAGS) -o $@

# The unit tests, then the cross-checks against openssl (and apksigner,
# keytool and Python's cryptography where they are installed).
test: all
	@set -e; for t in $(TESTS); do $$t; done; echo "all tests passed"
	@bash tests/cross_check.sh $(BUILD)/apkpack
	@bash tests/link_check.sh $(BUILD)/apkpack

clean:
	rm -r -f -- build
