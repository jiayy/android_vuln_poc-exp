SOURCES := $(wildcard src/*.c)
HEADERS := $(wildcard include/*.h)
OBJECTS := $(patsubst src/%.c,obj/%.o,$(SOURCES))
DEPENDS := $(patsubst src/%.c,obj/%.d,$(SOURCES))

CFLAGS = -I./include -Werror
LDFLAGS = -static -s

TARGET ?= poc

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

debug_boot:
	~/exp_sample/ks push rootfs.cpio $(TARGET) / && \
	./boot.sh
