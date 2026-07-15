# liblinkkeys_local_rp — plain Makefile, per dns-less-local-rp-design.md's
# "SDK Layout and Tooling" (no cmake/autotools; nothing here demands them).
#
# Toolchain: system GCC + OpenSSL 3.x via pkg-config. C11.
#
# Targets:
#   make            - build the static library (build/liblinkkeys_local_rp.a)
#   make test       - build and run the ASan/UBSan-instrumented test runner
#   make clean

CC ?= gcc
PKG_CONFIG ?= pkg-config

OPENSSL_CFLAGS := $(shell $(PKG_CONFIG) --cflags openssl 2>/dev/null)
OPENSSL_LIBS := $(shell $(PKG_CONFIG) --libs openssl 2>/dev/null)
ifeq ($(strip $(OPENSSL_LIBS)),)
OPENSSL_LIBS := -lssl -lcrypto
endif

INCLUDES := -Iinclude -Isrc
WARN := -Wall -Wextra -Wno-unused-parameter
CFLAGS ?= -std=c11 $(WARN) -g -O0 -D_GNU_SOURCE $(INCLUDES) $(OPENSSL_CFLAGS)
LDLIBS := $(OPENSSL_LIBS) -lresolv -lpthread

ASAN_FLAGS := -fsanitize=address,undefined -fno-omit-frame-pointer -fno-sanitize-recover=all

BUILD := build

SRC := $(wildcard src/*.c)
LIB_OBJS := $(patsubst src/%.c,$(BUILD)/lib/%.o,$(SRC))

TEST_SRC := $(wildcard tests/*.c)
TEST_SRC_OBJS := $(patsubst src/%.c,$(BUILD)/test/src_%.o,$(SRC))
TEST_TEST_OBJS := $(patsubst tests/%.c,$(BUILD)/test/tests_%.o,$(TEST_SRC))
TEST_BIN := $(BUILD)/test_runner

.PHONY: all lib test clean

all: lib

lib: $(BUILD)/liblinkkeys_local_rp.a

$(BUILD)/lib/%.o: src/%.c
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD)/liblinkkeys_local_rp.a: $(LIB_OBJS)
	ar rcs $@ $^

# Tests compile the library sources directly (not against the plain .a) so
# every line of the SDK — not just the test harness — runs under
# ASan/UBSan. A separately-instrumented lib build step would be redundant.
$(BUILD)/test/src_%.o: src/%.c
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $(ASAN_FLAGS) -c $< -o $@

$(BUILD)/test/tests_%.o: tests/%.c
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $(ASAN_FLAGS) -c $< -o $@

$(TEST_BIN): $(TEST_SRC_OBJS) $(TEST_TEST_OBJS)
	$(CC) $(CFLAGS) $(ASAN_FLAGS) -o $@ $^ $(LDLIBS)

test: $(TEST_BIN)
	./$(TEST_BIN)

clean:
	rm -rf $(BUILD)
