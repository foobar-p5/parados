CC ?= cc

CPPFLAGS = -D_POSIX_C_SOURCE=200809L
CFLAGS = -std=c99 -Wall -Wextra -O2 -Iserver/include
OUT = parados

all: parados

parados:
	$(CC) server/*.c -o $(OUT)

clean:
	rm -f $(OUT)

compile_flags:
	rm -f compile_flags.txt
	for f in ${CPPFLAGS} ${CFLAGS}; do echo $$f >> compile_flags.txt; done
