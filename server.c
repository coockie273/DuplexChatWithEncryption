#include <stdio.h>
#include <stdlib.h>
#include <libgen.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define MAX_DATA_SIZE 128

// get sockaddr, IPv4 or IPv6:
void *get_in_addr(struct sockaddr *sa)
{
    if (sa->sa_family == AF_INET) {
        return &(((struct sockaddr_in*)sa)->sin_addr);
    }

    return &(((struct sockaddr_in6*)sa)->sin6_addr);
}

void wait_send(int *fd)
{
    char sendbuf[MAX_DATA_SIZE];
    while(1)
    {
        memset(sendbuf, 0, MAX_DATA_SIZE);
        fgets(sendbuf, MAX_DATA_SIZE, stdin);

        int msg_length = strlen(sendbuf);
        sendbuf[msg_length] = '\0';

        if (send(*fd, sendbuf, msg_length+1, 0) < 0)
        {
            printf("Send failed\n");
            exit(1);
        }
    }
}

void wait_recv(int *fd)
{
    char recvbuf[MAX_DATA_SIZE];
    int msg_length;
    while(1)
    {
        memset(recvbuf, 0, MAX_DATA_SIZE);
        if (msg_length = recv(*fd, recvbuf, MAX_DATA_SIZE-1, 0) == -1)
        {
            perror("recv");
            exit(1);
        }
        recvbuf[msg_length] = '\0';
        printf("Received: %s", recvbuf);
    }
}

int main(int argc, char *argv[])
{
    if (argc != 2)
    {
        printf("Usage: %s port\n", basename(argv[0]));
        exit(-1);
    }

    char* port = argv[1];

    int listener;
    int yes = 1;
    int rv;

    struct addrinfo hints, *ai, *p;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;

    if (rv = getaddrinfo(NULL, port, &hints, &ai) != 0)
    {
        fprintf(stderr, "Selectserver: %s", gai_strerror(rv));
        exit(-1);
    }

    for (p = ai; p != NULL; p = p->ai_next)
    {
        listener = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        if (listener < 0) continue;

        setsockopt(listener, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int));

        if (bind(listener, p->ai_addr, p->ai_addrlen) < 0)
        {
            close(listener);
            continue;
        }

        break;
    }

    if (p == NULL)
    {
        fprintf(stderr, "Selectserver: failed to bind\n");
        exit(-1);
    }

    freeaddrinfo(ai);

    printf("Binding successfull\n");

    if(listen(listener, 1) == -1)
    {
        perror("listen");
        exit(-1);
    }

    printf("Waiting for incoming connection\n");
    int fd;

    while(1)
    {
        struct sockaddr_storage remoteaddr;
        socklen_t addrlen = sizeof(remoteaddr);

        fd = accept(listener, (struct sockaddr *)&remoteaddr, &addrlen);
        if (fd == -1) 
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
    pid_t pid = fork();
        
    if (pid < 0)
    {
        perror("Creating child process failed");
        exit(-1);
    }

    if (pid == 0)
        wait_send(&fd);
    else
        wait_recv(&fd);

    return 0;
}