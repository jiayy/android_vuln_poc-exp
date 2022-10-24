objects = ./pwn.o ./helpers.o 

.PHONY: clean pwn

pwn: $(objects)
	$(CC) $(objects) -lmnl -lnftnl -o pwn 

./%.o: %.c
	$(CC) -c $(CFLAGS) -o "$@" "$<"
	
clean:
	rm -rf ./pwn.o ./helpers.o