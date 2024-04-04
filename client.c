#include <stdio.h>
#include <stdlib.h>
#include <libgen.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <sys/types.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define MAX_DATA_SIZE 80


void send_message(int *sock)
{
    char sendbuf[MAX_DATA_SIZE];

    memset(sendbuf, 0, MAX_DATA_SIZE);
    //Обработка длины сообщения
    fgets(sendbuf, MAX_DATA_SIZE, stdin);

    int msg_length = strlen(sendbuf);
    sendbuf[msg_length] = '\0';

    if (msg_length >= MAX_DATA_SIZE) {
        printf("The message is too long");
        return;
    }

    if (send(*sock, sendbuf, msg_length + 1, 0) < 0)
    {
        perror("Send failed");
    }

}

int recv_message(int *sock)
{
    char recvbuf[MAX_DATA_SIZE];
    int msg_length;

    memset(recvbuf, 0, MAX_DATA_SIZE);
    if (msg_length = recv(*sock, recvbuf, MAX_DATA_SIZE-1, 0) == -1)
    {
        perror("recv");
    }

    if (recvbuf[0] == '\0') return 0;

    printf("Received: %s", recvbuf);
    return 1;
}


int main(int argc, char *argv[])
{
    if (argc != 3)
    {
        printf("Usage: %s hostname port", basename(argv[0]));
        exit(-1);
    }

    char* hostname = argv[1];
    char* port = argv[2];
    int port_int = atoi(port);

    int sock;

    struct sockaddr_in addr;

    sock = socket(AF_INET, SOCK_STREAM, 0);

    if (sock < 0) {

        perror("socket");
        exit(-1);
    }

    addr.sin_family = AF_INET;
    addr.sin_port = htons(port_int);

    // hostname в структуру in_addr
    if (inet_pton(AF_INET, hostname, &addr.sin_addr) <= 0) {
        perror("inet_pton");
        exit(-1);
    }

    if (connect(sock, (struct sockaddr *) &addr, sizeof(addr)) < 0) {

        perror("connect");
        exit(-1);

    }

    fd_set read_fds;

    FD_ZERO(&read_fds);
    FD_SET(sock, &read_fds);
    FD_SET(STDIN_FILENO, &read_fds);

    int max_fd = (sock > STDIN_FILENO) ? sock : STDIN_FILENO;

    while (1) {
        fd_set temp_fds = read_fds;

        // Бесконечно ждем активности
        int activity = select(max_fd + 1, &temp_fds, NULL, NULL, NULL);
        if (activity < 0) {
            perror("Error in select");
            exit(EXIT_FAILURE);
        }

        // Проверяем сообщение от сервера
        if (FD_ISSET(sock, &temp_fds)) {
            if (! recv_message(&sock)) {
                close(sock);
                break;
            }
        }

        // Проверяем поток stdin
        if (FD_ISSET(STDIN_FILENO, &temp_fds)) {
            send_message(&sock);
        }

    }

    return 0;
}

