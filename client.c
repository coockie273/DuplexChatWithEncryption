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

#define PORT 80
#define MAX_DATA_SIZE 80


void wait_send(int *sock)
{
    char sendbuf[MAX_DATA_SIZE];
    printf("Sender mode on");
    while(1)
    {
        memset(sendbuf, 0, MAX_DATA_SIZE);
        // Проверка maxsize
        fgets(sendbuf, MAX_DATA_SIZE, stdin);

        int msg_length = strlen(sendbuf);
        sendbuf[msg_length] = '\0';

        if (send(*sock, sendbuf, msg_length+1, 0) < 0)
        {
            perror("Send failed");
        }
    }
}

void wait_recv(int *sock)
{
    printf("Recv mode on");
    char recvbuf[MAX_DATA_SIZE];
    int msg_length;
    while(1)
    {
        memset(recvbuf, 0, MAX_DATA_SIZE);
        if (msg_length = recv(*sock, recvbuf, MAX_DATA_SIZE-1, 0) == -1)
        {
            perror("recv");
            exit(1);
        }
        recvbuf[msg_length] = '\0';
        printf("Received: %s", recvbuf);
    }
}

void print1() {
    printf("print1");
    while(1) {};
}

void print2() {
    printf("print2");
    while(1) {};
}


int main(int argc, char *argv[])
{
    if (argc != 2)
    {
        printf("Usage: %s hostname", basename(argv[0]));
        exit(-1);
    }

    char* hostname = argv[1];

    int sock;

    struct sockaddr_in addr;

    sock = socket(AF_INET, SOCK_STREAM, 0);

    if (sock < 0) {

        perror("socket");
        exit(-1);
    }

    addr.sin_family = AF_INET;
    addr.sin_port = htons(PORT);

    // hostname в структуру in_addr
    if (inet_pton(AF_INET, hostname, &addr.sin_addr) <= 0) {
        perror("inet_pton");
        exit(-1);
    }

    if (connect(sock, (struct sockaddr *) &addr, sizeof(addr)) < 0) {

        perror("connect");
        exit(-1);

    }

    pid_t pid = fork();

    if (pid < 0)
    {
        perror("Creating child process failed");
        exit(-1);
    }

    if (pid == 0)
    {
        printf("Child process (PID: %d)\n", getpid());
        //wait_send(&sock);
        print1();
    }
    else
    {
        printf("Parent process (PID: %d)\n", getpid());
        //wait_recv(&sock);
        print2();
    }
    return 0;
}
