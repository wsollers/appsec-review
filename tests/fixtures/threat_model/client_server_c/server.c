/* Inert fixture for the generated DFD and threat model (T-107): a line-echo server.
 * It exists to give the structure and interaction lanes something small to describe.
 * It holds no seeded defect and there is no answer key. */
#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define PORT 7000
#define LINE 256

static int read_greeting(char *greeting, size_t size) {
    FILE *file = fopen("greeting.txt", "r");
    if (file == NULL) {
        return -1;
    }
    if (fgets(greeting, (int)size, file) == NULL) {
        greeting[0] = '\0';
    }
    fclose(file);
    return 0;
}

static void serve(int peer, const char *greeting) {
    char line[LINE];
    ssize_t count = recv(peer, line, sizeof(line) - 1, 0);
    if (count <= 0) {
        return;
    }
    line[count] = '\0';
    send(peer, greeting, strlen(greeting), 0);
    send(peer, line, (size_t)count, 0);
}

int main(void) {
    char greeting[LINE] = "hello\n";
    struct sockaddr_in address;
    int listener = socket(AF_INET, SOCK_STREAM, 0);
    if (listener < 0) {
        return 1;
    }
    read_greeting(greeting, sizeof(greeting));
    memset(&address, 0, sizeof(address));
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    address.sin_port = htons(PORT);
    if (bind(listener, (struct sockaddr *)&address, sizeof(address)) != 0 || listen(listener, 4) != 0) {
        close(listener);
        return 1;
    }
    for (;;) {
        int peer = accept(listener, NULL, NULL);
        if (peer < 0) {
            break;
        }
        serve(peer, greeting);
        close(peer);
    }
    close(listener);
    return 0;
}
