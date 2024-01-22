DEBUG=-g
CC=clang
CFLAGS=-Wall -Wextra -pedantic \
			-Wno-unused-parameter -Wno-unused-function -Wno-unused-variable \
			-std=c17 $(pkg-config --cflags gtk4) \
			$(DEBUG)
LDFLAGS=$(pkg-config --libs gtk4)
BINARY=main
OBJECTS=main.o sha256.o

default: $(BINARY)

$(BINARY): $(OBJECTS)

run:
	make clean
	make
	./$(BINARY)

clean:
	@echo "Cleaning Up"
	rm -f $(BINARY) $(OBJECTS)