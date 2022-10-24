SOURCES := $(wildcard src/*.c)
HEADERS := $(wildcard include/*.h)
OBJECTS := $(patsubst src/%.c,obj/%.o,$(SOURCES))
DEPENDS := $(patsubst src/%.c,obj/%.d,$(SOURCES))

CFLAGS = -I./include -Werror
LDFLAGS = -static -s

TARGET ?= exploit

.PHONY: all clean

all: obj $(TARGET)

$(TARGET): $(OBJECTS)
	$(CC) $(LDFLAGS) $^ -o $@

-include $(DEPENDS)

obj/%.o: src/%.c Makefile
	$(CC) $(CFLAGS) -MMD -MP -c $< -o $@

obj:
	mkdir -p obj

clean:
	rm -rf obj
	rm -f $(TARGET)

