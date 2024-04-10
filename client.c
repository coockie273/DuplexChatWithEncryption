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


void print_secret_key(const unsigned char *key, size_t key_len) {
    printf("Secret key (hex): ");
    for (size_t i = 0; i < key_len; ++i) {
        printf("%02x", key[i]);
    }
    printf("\n");
}

void generate_session_key(int *sock) {

    // Creating dh context with hardcoded p and g
    EVP_PKEY_CTX *dh_params_ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_DH, NULL);
    if (!dh_params_ctx) {
        perror("Ошибка при создании контекста параметров домена");
        exit(EXIT_FAILURE);
    }

    int g = 7;
    int p = 103;

    if (EVP_PKEY_CTX_set_dh_paramgen_prime_len(dh_params_ctx, 1024) <= 0) {
        perror("Ошибка при установке параметров домена");
        exit(EXIT_FAILURE);
    }

    EVP_PKEY *params = NULL;
    if (EVP_PKEY_paramgen(dh_params_ctx, &params) <= 0) {
        perror("Ошибка при генерации параметров домена");
        exit(EXIT_FAILURE);
    }

    EVP_PKEY_CTX *keygen_ctx = EVP_PKEY_CTX_new(params, NULL);
    if (!keygen_ctx) {
        perror("Ошибка при создании контекста ключевой пары");
        exit(EXIT_FAILURE);
    }

    EVP_PKEY *keypair = NULL;
    if (EVP_PKEY_keygen_init(keygen_ctx) <= 0 ||
        EVP_PKEY_keygen(keygen_ctx, &keypair) <= 0) {
        perror("Ошибка при генерации ключевой пары");
        exit(EXIT_FAILURE);
    }

    // Get server public key
    size_t other_pub_key_len = 0;
    if (recv(*sock, &other_pub_key_len, sizeof(size_t), 0) < 0) {
        perror("Ошибка при получении длины публичного ключа другой стороны");
        exit(EXIT_FAILURE);
    }
    unsigned char *other_pub_key_data = malloc(other_pub_key_len);
    if (!other_pub_key_data ||
        recv(*sock, other_pub_key_data, other_pub_key_len, 0) < 0) {
        perror("Ошибка при получении публичного ключа другой стороны");
        exit(EXIT_FAILURE);
    }

    EVP_PKEY *other_pub_key = EVP_PKEY_new_raw_public_key(EVP_PKEY_DH, NULL,
                                                           other_pub_key_data,
                                                           other_pub_key_len);
    if (!other_pub_key) {
        perror("Ошибка при создании публичного ключа другой стороны");
        exit(EXIT_FAILURE);
    }

    // Generating and sending public client key
    unsigned char *pub_key_data = NULL;
    size_t pub_key_len = 0;
    if (EVP_PKEY_get_raw_public_key(keypair, NULL, &pub_key_len) <= 0 ||
        !(pub_key_data = malloc(pub_key_len)) ||
        EVP_PKEY_get_raw_public_key(keypair, pub_key_data, &pub_key_len) <= 0 ||
        send(*sock, &pub_key_len, sizeof(size_t), 0) < 0 ||
        send(*sock, pub_key_data, pub_key_len, 0) < 0) {
        perror("Ошибка при отправке публичного ключа");
        exit(EXIT_FAILURE);
    }
    free(pub_key_data);

    EVP_PKEY_CTX *derive_ctx = EVP_PKEY_CTX_new(keypair, NULL);
    if (!derive_ctx) {
        perror("Ошибка при создании контекста для вычисления общего секрета");
        exit(EXIT_FAILURE);
    }

    if (EVP_PKEY_derive_init(derive_ctx) <= 0 ||
        EVP_PKEY_derive_set_peer(derive_ctx, other_pub_key) <= 0 ||
        EVP_PKEY_derive(derive_ctx, NULL, &session_key_len) <= 0) {
        perror("Ошибка при вычислении общего секрета");
        exit(EXIT_FAILURE);
    }

    // Generate session key
    session_key = malloc(session_key_len);
    if (! session_key ||
        EVP_PKEY_derive(derive_ctx, session_key, &session_key_len) <= 0) {
        perror("Ошибка при вычислении общего секрета");
        exit(EXIT_FAILURE);
    }

    print_secret_key(session_key, session_key_len);

    // free memory
    EVP_PKEY_free(params);
    EVP_PKEY_free(keypair);
    EVP_PKEY_free(other_pub_key);
    EVP_PKEY_CTX_free(dh_params_ctx);
    EVP_PKEY_CTX_free(keygen_ctx);
    EVP_PKEY_CTX_free(derive_ctx);
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

