CC = gcc
CFLAGS = -std=c11 -Wall -Wextra -Wpedantic -Werror \
         -I./src/core -I./src/ssh -I./src/events -I./src/storage \
         -I./src/intel -I./src/alerting -I./src/mgmt \
         -D_GNU_SOURCE -D_FORTIFY_SOURCE=2 \
         -fstack-protector-strong -fPIE
LDFLAGS = -pie -Wl,-z,relro,-z,now
LIBS = -lssh -lsqlite3 -ljson-c -lcurl -luuid -lpthread -lcrypto

ifeq ($(DEBUG),1)
CFLAGS += -g -O0 -fsanitize=address,undefined
LDFLAGS += -fsanitize=address,undefined
else
CFLAGS += -O2
endif

SRCS = src/main.c \
       src/core/dolus.c \
       src/core/config.c \
       src/core/logging.c \
       src/ssh/ssh_engine.c \
       src/events/event.c \
       src/events/session.c \
       src/storage/storage.c \
       src/intel/intel.c \
       src/alerting/alerting.c \
       src/mgmt/cli.c

OBJS = $(SRCS:.c=.o)
TARGET = bin/dolus

all: $(TARGET)

$(TARGET): $(OBJS)
	@mkdir -p bin
	$(CC) $(LDFLAGS) -o $@ $^ $(LIBS)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJS) $(TARGET) *~ src/*~ src/**/*~

install: $(TARGET)
	install -d /usr/local/bin
	install -m 755 $(TARGET) /usr/local/bin/dolus
	install -d /etc/dolus
	install -m 644 dolus.conf.example /etc/dolus/dolus.conf 2>/dev/null || true
	install -d /var/lib/dolus
	install -d /var/log/dolus
	install -d /var/run/dolus

uninstall:
	rm -f /usr/local/bin/dolus
	rm -f /etc/dolus/dolus.conf
	rm -rf /var/lib/dolus
	rm -rf /var/log/dolus
	rm -rf /var/run/dolus

test: CFLAGS += -DTEST_BUILD
test: $(TARGET)
	@echo "Running tests..."
	@./bin/dolus --version

static-analysis:
	cppcheck --enable=all --std=c11 --suppress=missingIncludeSystem src/
	clang-tidy src/*.c src/**/*.c -- -I./src/core -I./src/ssh -I./src/events -I./src/storage -I./src/intel -I./src/alerting -I./src/mgmt

format:
	clang-format -i src/*.c src/**/*.c src/**/*.h

.PHONY: all clean install uninstall test static-analysis format