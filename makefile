CC = gcc
CFLAGS = -g -Wextra -Wall -std=gnu99 -Iinclude -Wno-unused-parameter -Wno-unused-variable -Wno-duplicate-decl-specifier
MQTT_C_SOURCES = src/mqtt.c src/mqtt_pal.c
MQTT_C_EXAMPLES = bin/main
BINDIR = bin

all: $(BINDIR) $(MQTT_C_EXAMPLES)

bin/main: main.c $(MQTT_C_SOURCES)
	$(CC) $(CFLAGS) $^ -lpthread -lssl -lcrypto -L/usr/local/lib -lcjson -o $@

$(BINDIR):
	mkdir -p $(BINDIR)
clean:
	rm -rf $(BINDIR)