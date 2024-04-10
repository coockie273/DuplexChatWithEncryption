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

    EVP_PKEY_CTX *kctx = NULL;
    EVP_PKEY *dhkey = NULL;
    EVP_PKEY *params = NULL;
    BIO* fp = NULL;

    if (!(params = EVP_PKEY_new())) {
        fprintf(stderr, "Error for params creating\n");
        exit(-1);
    }

    if (1 != EVP_PKEY_assign(params, EVP_PKEY_DHX, DH_get_2048_256())) {
        fprintf(stderr, "Error in assign\n");
        exit(-1);
    }

    if (!(kctx = EVP_PKEY_CTX_new(params, NULL))) {
        fprintf(stderr, "Error in initializing kctx\n");
        exit(-1);
    }

    if (1 != EVP_PKEY_keygen_init(kctx)) {
        fprintf(stderr, "Error in key generation\n");
        exit(-1);
    }

    if (1 != EVP_PKEY_keygen(kctx, &dhkey)) {
        fprintf(stderr, "Error in key generation\n");
        exit(-1);
    }

    fp = BIO_new_fp(stdout, BIO_NOCLOSE);
    if (fp == NULL) {
        fprintf(stderr, "Error creating BIO\n");
        exit(-1);
    }

    EVP_PKEY_print_private(fp, dhkey, 0, NULL);

    DH *dh = EVP_PKEY_get1_DH(dhkey);
    if (dh == NULL) {
        fprintf(stderr, "Error getting DH structure\n");
        exit(-1);
    }

    unsigned char server_public_key[1024];
    int bytes_received = recv(*sock, server_public_key, sizeof(server_public_key), 0);
    if (bytes_received < 0) {
        fprintf(stderr, "Error receiving server's public key\n");
        exit(-1);
    }

    printf(server_public_key);

    const BIGNUM *pub_key_bn;
    DH_get0_key(dh, &pub_key_bn, NULL);
    unsigned char *pub_key_bytes = (unsigned char *)malloc(DH_size(dh));
    if (pub_key_bytes == NULL) {
        fprintf(stderr, "Error allocating memory\n");
        exit(-1);
    }

    int pub_key_len = BN_bn2bin(pub_key_bn, pub_key_bytes);

    send(*sock, pub_key_bytes, pub_key_len, 0);
    printf("Public key server to client\n");

    if (1 != EVP_PKEY_derive_init(kctx)) {
        fprintf(stderr, "Error deriving\n");
        exit(-1);
    }

    if (1 != EVP_PKEY_derive_set_peer(kctx, server_public_key)) {
        fprintf(stderr, "Error in settning client public key\n");
        exit(-1);
    }

    if (1 != EVP_PKEY_derive(kctx, NULL, &session_key_len)) {
        fprintf(stderr, "Error deriving\n");
        exit(-1);
    }

    session_key = (unsigned char *)malloc(session_key_len);

    if (1 != (EVP_PKEY_derive(kctx, session_key, &session_key_len))) {
        fprintf(stderr, "Error in creating session key\n");
        exit(-1);
    }

    EVP_PKEY_free(params);
    EVP_PKEY_CTX_free(kctx);
    EVP_PKEY_free(dhkey);
    BIO_free(fp);

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

