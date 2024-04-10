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
#include <openssl/dh.h>
#include <openssl/evp.h>

#define MAX_DATA_SIZE 80
#define KEY_SIZE 16

int crypto = 0;
unsigned char *session_key;
size_t session_key_len;


void generate_session_key(int *sock) {

    DH *privkey;
    int codes;
    int secret_size;

    /* Generate the parameters to be used */
    if(NULL == (privkey = DH_new())) {
        fprintf(stderr, "Error for initialize DH\n");
        exit(-1);
    }
    if(1 != DH_generate_parameters_ex(privkey, 2048, DH_GENERATOR_2, NULL)) {
        fprintf(stderr, "Error for params creating\n");
        exit(-1);
    }

    if(1 != DH_check(privkey, &codes)) {
        fprintf(stderr, "Error for DH check\n");
        exit(-1);
    }

    if(codes != 0)
    {
        /* Problems have been found with the generated parameters */
        /* Handle these here - we'll just abort for this example */
        printf("DH_check failed\n");
        exit(-1);
    }

    /* Generate the public and private key pair */
    if(1 != DH_generate_key(privkey)) {
        fprintf(stderr, "Error for generating key\n");
        exit(-1);
    }

    /* Send the public key to the peer.
    * How this occurs will be specific to your situation (see main text below) */

    unsigned char server_public_key[1024];
    int bytes_received = recv(*sock, client_public_key, sizeof(server_public_key), 0);
    if (bytes_received < 0) {
        fprintf(stderr, "Error receiving server's public key\n");
        exit(-1);
    }

    const BIGNUM *pub_key_bn;
    DH_get0_key(privkey, &pub_key_bn, NULL);
    unsigned char *pub_key_bytes = (unsigned char *)malloc(DH_size(privkey));
    if (pub_key_bytes == NULL) {
        fprintf(stderr, "Error allocating memory\n");
        exit(-1);
    }

    int pub_key_len = BN_bn2bin(pub_key_bn, pub_key_bytes);

    send(*sock, pub_key_bytes, pub_key_len, 0);
    printf("Public key sent to server\n");


    /* Receive the public key from the peer. In this example we're just hard coding a value */
    BIGNUM *pubkey = NULL;
    if(0 == (BN_dec2bn(&pubkey, server_public_key))) {
        fprintf(stderr, "Error for decode public client key creating\n");
        exit(-1);
    }

    /* Compute the shared secret */

    if(NULL == (session_key = OPENSSL_malloc(sizeof(unsigned char) * (DH_size(privkey))))) {
        fprintf(stderr, "Memory error\n");
        exit(-1);
    }

    if(0 > (session_key_len = DH_compute_key(session_key, pubkey, privkey))) {
        fprintf(stderr, "Error in computing secret\n");
        exit(-1);
    }

    /* Do something with the shared secret */
    /* Note secret_size may be less than DH_size(privkey) */
    printf("The shared secret is:\n");
    BIO_dump_fp(stdout, session_key, session_key_len);

    /* Clean up */
    OPENSSL_free(session_key_len);
    BN_free(pubkey);
    DH_free(privkey);

}

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
    char* hostname = argv[1];
    char* port = argv[2];
    int port_int = atoi(port);

    int sock;

    struct sockaddr_in addr;

    // socker for connection to server
    sock = socket(AF_INET, SOCK_STREAM, 0);

    if (sock < 0) {

        perror("socket");
        exit(-1);
    }

    addr.sin_family = AF_INET;
    addr.sin_port = htons(port_int);

    // hostname at structure in_addr
    if (inet_pton(AF_INET, hostname, &addr.sin_addr) <= 0) {
        perror("inet_pton");
        exit(-1);
    }

    // connect with server
    if (connect(sock, (struct sockaddr *) &addr, sizeof(addr)) < 0) {

        perror("connect");
        exit(-1);

    }

    // get info about encryption from client
    if (recv(sock, &crypto, MAX_DATA_SIZE-1, 0) == -1)
    {
        perror("recv");
    }

    crypto = ntohl(crypto);
    // Generation key for crypto mode
    if (crypto) {
       generate_session_key(&sock);
       printf("Ключ шифрования был успешно сгенерирован\n");
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

