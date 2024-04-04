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

// get sockaddr, IPv4 or IPv6:
void *get_in_addr(struct sockaddr *sa)
{
    if (sa->sa_family == AF_INET) {
        return &(((struct sockaddr_in*)sa)->sin_addr);
    }

    return &(((struct sockaddr_in6*)sa)->sin6_addr);
}

void send_message(int *sock)
{
    char sendbuf[MAX_DATA_SIZE];

    memset(sendbuf, 0, MAX_DATA_SIZE);
    fgets(sendbuf, MAX_DATA_SIZE, stdin);

    int msg_length = strlen(sendbuf);
    sendbuf[msg_length] = '\0';
    msg_length += 1;

    if (msg_length >= MAX_DATA_SIZE) {
        printf("The message is too long\n");
        return;
    }

    if (send(*sock, sendbuf, msg_length+1, 0) < 0)
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

    if (recvbuf[0] == '\0')  return 0;

    printf("Received: %s", recvbuf);
    return 1;
}


int main(int argc, char *argv[])
{
    if (argc != 2)
    {
        printf("Usage: %s port", basename(argv[0]));
        exit(-1);
    }

    char* port = argv[1];
    int port_int = atoi(port);


    struct sockaddr_in addr;
    int yes = 1;

    int listener = socket(AF_INET, SOCK_STREAM, 0);

    if (listener < 0) {
        perror("Failed to create listener socket");
        exit(-1);
    }

    addr.sin_family = AF_INET;
    addr.sin_port = htons(port_int);
    addr.sin_addr.s_addr = htonl(INADDR_ANY);

    setsockopt(listener, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int));

    if (bind(listener, (struct sockaddr *)&addr, sizeof(addr)) < 0) {

       perror("Failed to bind listener");
       exit(-1);

    }

    printf("Binding successfull\n");

    if(listen(listener, 1) == -1)
    {
        perror("listen");
        exit(-1);
    }

    printf("Waiting for incoming connection\n");
    int client_sock;

    while(1)
    {
        struct sockaddr_storage remoteaddr;
        socklen_t addrlen = sizeof(remoteaddr);

        client_sock = accept(listener, (struct sockaddr *)&remoteaddr, &addrlen);
        if (client_sock == -1)
        {
            perror("accept");
            continue;
        }

        char remoteIP[INET6_ADDRSTRLEN];
        inet_ntop(remoteaddr.ss_family, get_in_addr((struct sockaddr *)&remoteaddr), remoteIP, sizeof(remoteIP));
        printf("Connection established with %s\n", remoteIP);
        close(listener);
        break;
    }

    fd_set read_fds;

    FD_ZERO(&read_fds);
    FD_SET(client_sock, &read_fds);
    FD_SET(STDIN_FILENO, &read_fds);

    int max_fd = (client_sock > STDIN_FILENO) ? client_sock : STDIN_FILENO;

    while (1) {
        fd_set temp_fds = read_fds;

        // Бесконечно ждем активности
        int activity = select(max_fd + 1, &temp_fds, NULL, NULL, NULL);
        if (activity < 0) {
            perror("Error in select");
            exit(EXIT_FAILURE);
        }

        // Проверяем сообщение от клиента
        if (FD_ISSET(client_sock, &temp_fds)) {
            if (! recv_message(&client_sock)) {
                close(client_sock);
                break;
            }
        }

        // Проверяем поток stdin
        if (FD_ISSET(STDIN_FILENO, &temp_fds)) {
            send_message(&client_sock);
        }

    }

    return 0;
}
