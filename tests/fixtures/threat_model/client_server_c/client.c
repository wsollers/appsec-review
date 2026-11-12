/* Inert fixture for the generated DFD and threat model (T-107): the client of server.c.
 * It sends one line and prints the reply. No seeded defect, no answer key. */
#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define PORT 7000
#define LINE 256

int main(int argc, char **argv) {
    const char *message = argc > 1 ? argv[1] : "ping\n";
    char reply[LINE];
    struct sockaddr_in address;
    ssize_t count;
    int peer = socket(AF_INET, SOCK_STREAM, 0);
    if (peer < 0) {
        return 1;
    }
    memset(&address, 0, sizeof(address));
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    address.sin_port = htons(PORT);
    if (connect(peer, (struct sockaddr *)&address, sizeof(address)) != 0) {
        close(peer);
        return 1;
    }
    send(peer, message, strlen(message), 0);
    count = recv(peer, reply, sizeof(reply) - 1, 0);
    if (count > 0) {
        reply[count] = '\0';
        fputs(reply, stdout);
    }
    close(peer);
    return 0;
}
