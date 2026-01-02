#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include <arpa/inet.h>
#include <netinet/in.h>

#define PORT   6767

void die(const char* s, int e);

void die(const char* s, int e)
{
	perror(s);
	exit(e);
}

int main(void)
{
	int ret = 1;
	int s = socket(AF_INET, SOCK_STREAM, 0);
	if (s < 0)
		die("socket", EXIT_FAILURE);

	int yes = 1;
	ret = setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));
	if (ret < 0)
		die("setsockopt", EXIT_FAILURE);

	struct sockaddr_in a;
	memset(&a, 0, sizeof(a));
	a.sin_family = AF_INET;
	a.sin_port = htons(PORT);
	a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

	ret = bind(s, (struct sockaddr*)&a, sizeof(a));
	if (ret < 0)
		die("bind", EXIT_FAILURE);

	ret = listen(s, 64);
	if (ret < 0)
		die("listen", EXIT_FAILURE);

	printf("listening on 127.0.0.1:%d\n", PORT);

	for (;;) {
		int c = accept(s, NULL, NULL);
		if (c < 0)
			continue;

		(void)write(c, "hello\n", 6);
		shutdown(c, SHUT_WR);
		close(c);
	}

	return EXIT_SUCCESS;
}
