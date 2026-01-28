CC ?= cc
GIT_VER != git describe --always --tags 2>/dev/null || echo unknown
CPPFLAGS = -D_POSIX_C_SOURCE=200809L -DGIT_VER=\"$(GIT_VER)\"
CFLAGS = -std=c99 -Wall -Wextra -Iserver/include
OUT = parados

all: release

release:
	$(CC) $(CPPFLAGS) -DNDEBUG $(CFLAGS) -O2 server/*.c -o $(OUT)

debug:
	$(CC) $(CPPFLAGS) -DDEBUG $(CFLAGS) -g server/*.c -o $(OUT)

clean:
	rm -f $(OUT)

compile_flags:
	rm -f compile_flags.txt
	for f in ${CPPFLAGS} ${CFLAGS}; do echo $$f >> compile_flags.txt; done
