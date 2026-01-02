CC=cc

CPPFLAGS=
CFLAGS= -Iserver/include

DAE=paradosd

all: parados

parados:
	$(CC) server/*.c -o $(DAE)

clangd:
	rm -f compile_flags.txt
	for f in ${CPPFLAGS} ${CFLAGS}; do echo $$f >> compile_flags.txt; done
