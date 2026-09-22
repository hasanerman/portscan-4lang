CC ?= cc
CPPFLAGS := -D_POSIX_C_SOURCE=200809L -pthread
CFLAGS ?= -std=c11 -O2 -Wall -Wextra -Wpedantic -Wshadow -Wconversion
LDLIBS := -pthread
BUILD := build

CORE := src/ports.c src/args.c src/net_addr.c src/net_sock.c src/scan.c src/pool.c src/report.c
APP := $(BUILD)/portscan
TESTS := $(BUILD)/test_ports $(BUILD)/test_scan $(BUILD)/test_report

.PHONY: all test asan clean

all: $(APP)

$(BUILD):
	mkdir -p $(BUILD)

$(APP): src/main.c $(CORE) | $(BUILD)
	$(CC) $(CPPFLAGS) $(CFLAGS) -o $@ src/main.c $(CORE) $(LDLIBS)

$(BUILD)/test_%: tests/test_%.c $(CORE) | $(BUILD)
	$(CC) $(CPPFLAGS) $(CFLAGS) -o $@ $< $(CORE) $(LDLIBS)

test: $(TESTS)
	./$(BUILD)/test_ports
	./$(BUILD)/test_scan
	./$(BUILD)/test_report

asan: CFLAGS += -fsanitize=address,undefined -g -O1
asan: clean test

clean:
	rm -rf $(BUILD)
