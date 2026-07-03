#include <stddef.h>

int receive_msg(const char *buf, int len, const void *rcvinfo) { return len; }
int udp_send(void *dst, const char *buf, unsigned len) { return (int)len; }
int tcp_send(void *dst, void *from, const char *buf, unsigned len) { return (int)len; }
int proto_udp_send(void *source, char *buf, unsigned len, void *to, unsigned id) { return (int)len; }
int proto_tcp_send(void *source, char *buf, unsigned len, void *to, unsigned id) { return (int)len; }

int main(void) { return 0; }
