#ifndef HTTP_H
#define HTTP_H

#define HTTP_200    "HTTP/1.1 200 OK\r\n"
#define HTTP_400    "HTTP/1.1 400 Bad Request\r\n"
#define HTTP_404    "HTTP/1.1 404 Not Found\r\n"
#define HTTP_405    "HTTP/1.1 405 Method Not Allowed\r\n"

#define HTTP_TEXT   "Content-Type: text/plain\r\n"
#define HTTP_CLOSE  "Connection: close\r\n"
#define HTTP_LENGTH "Content-Length: %zu\r\n"

int http_handle(char c);

#endif /* HTTP_H */

