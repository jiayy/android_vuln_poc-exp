
all:
	mkdir -p bin/
	gcc -g -o bin/exp \
			./liburing/test/helpers.c \
			-I./liburing/src/include/ \
			-w -O2  ./liburing/src/liburing.a \
			cross_cache.c msg.c manager.c tls.c main.c \
			-static -lrt -lpthread -luring \
			-Wl,--whole-archive -Wl,--no-whole-archive

clean:
	rm -r bin
