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
#include <openssl/blowfish.h>


#define MAX_DATA_SIZE 80
#define KEY_SIZE 16

int crypto = 0;
unsigned char* session_key;
size_t session_key_len;


void generate_session_key(int *sock) {

    DH *privkey;
    int codes;

    printf("Generating session key with DH algorithm...\n");

    /* Generate the parameters to be used */
    if(NULL == (privkey = DH_new())) {
        fprintf(stderr, "Error for initialize DH\n");
        exit(-1);
    }

    /* Hardcode parameters */

    BIGNUM *p = BN_new();
    BIGNUM *g = BN_new();

    BN_hex2bn(&p, "EAA9EC1C02ED05D6F6667E779DEDD4D1B152EC06E2D7FEE12A516367AE13655185D16958F96A19BE930813223C4E2596F695F38F5C565217469A5E3193B3B388903EA022706C6E083E7E1EC21D83145FFAC6BE218A17B0FA37DD1C7DED700E1B0503FDE772B6B15F0E8FDF91216517B413CAFE68C98187219C319C713981710F");
    BN_hex2bn(&g, "02");

    /* Set parameters*/
    if(1 != DH_set0_pqg(privkey, p, 0, g)) {
        fprintf(stderr, "Error for params creating\n");
        exit(-1);
    }

    /* Check parameters */
    if(1 != DH_check(privkey, &codes)) {
        fprintf(stderr, "Error for DH check\n");
        exit(-1);
    }

    if(codes != 0)
    {
        printf("DH_check failed\n");
        exit(-1);
    }

    /* Generate the public and private key pair */
    if(1 != DH_generate_key(privkey)) {
        fprintf(stderr, "Error for generating key\n");
        exit(-1);
    }

    char *pub_key = BN_bn2hex(DH_get0_pub_key(privkey));

    send(*sock, pub_key, strlen(pub_key), 0);
    free(pub_key);

    char server_pub_key[1024];
    int bytes_received = recv(*sock, server_pub_key, sizeof(server_pub_key), 0);
    if (bytes_received < 0) {
        fprintf(stderr, "Error receiving server's public key\n");
        exit(-1);
    }

    BIGNUM *bn_server_pub_key = BN_new();
    BN_hex2bn(&bn_server_pub_key, server_pub_key);;

    /* Compute the shared secret */

    session_key = malloc(sizeof(privkey));

    if(0 > (session_key_len = DH_compute_key(session_key, bn_server_pub_key, privkey))) {
        fprintf(stderr, "Error in computing secret\n");
        exit(-1);
    }

}

void bf_crypt(const char * message, const char* enc_message, int enc) {

    BF_KEY bfkey;
    BF_set_key(&bfkey, session_key_len, session_key);

    for (int i = 0; i < MAX_DATA_SIZE / 8; i++)
    {
        const char *current_block = message + i * 8;
        char *dest_block = enc_message + i * 8;
        BF_ecb_encrypt(current_block, dest_block, &bfkey, enc);

    }

}

void send_message(int *sock)
{
    char sendbuf[MAX_DATA_SIZE];

    memset(sendbuf, 0, MAX_DATA_SIZE);

    fgets(sendbuf, MAX_DATA_SIZE, stdin);

    int msg_length = strlen(sendbuf);
    sendbuf[msg_length] = '\0';

    // Prohibition on sending empty messages
    if (strcmp(sendbuf, "\n") == 0) return;

    // Encrypting message in crypto mode
    if (crypto) {
        char sendbuf_enc[MAX_DATA_SIZE];
        memset(sendbuf_enc, 0, MAX_DATA_SIZE);
        bf_crypt(sendbuf, sendbuf_enc, 0);
        int len;
        if (len = send(*sock, sendbuf_enc, MAX_DATA_SIZE, 0) < 0)
        {
            perror("Send failed");
        }
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

    // Receive message
    if (msg_length = recv(*sock, recvbuf, MAX_DATA_SIZE, 0) == -1)
    {
        perror("recv");
    }

    // Close connection when an empty message is received
    if (recvbuf[0] == '\0') return 0;

    // Decrypt message in crypto mode
    if (crypto) {
        char recvbuf_enc[MAX_DATA_SIZE];
        memset(recvbuf_enc, 0, MAX_DATA_SIZE);
        bf_crypt(recvbuf, recvbuf_enc, 1);
        printf("Received: %s", recvbuf_enc);
        return 1;
    }

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

    // get info about encryption from server
    if (recv(sock, &crypto, MAX_DATA_SIZE-1, 0) == -1)
    {
        perror("recv");
    }

    crypto = ntohl(crypto);

    // Generation key for crypto mode
    if (crypto) {
       generate_session_key(&sock);
       printf("The encryption key has been successfully generated\n");
    }

    fd_set read_fds;

    FD_ZERO(&read_fds);
    FD_SET(sock, &read_fds);
    FD_SET(STDIN_FILENO, &read_fds);

    int max_fd = (sock > STDIN_FILENO) ? sock : STDIN_FILENO;

    while (1) {
        fd_set temp_fds = read_fds;

        // Waiting for actions
        int activity = select(max_fd + 1, &temp_fds, NULL, NULL, NULL);
        if (activity < 0) {
            perror("Error in select");
            exit(EXIT_FAILURE);
        }

        // Check messages from server
        if (FD_ISSET(sock, &temp_fds)) {
            if (! recv_message(&sock)) {
                close(sock);
                break;
            }
        }

        // Check input from stdin
        if (FD_ISSET(STDIN_FILENO, &temp_fds)) {
            send_message(&sock);
        }

    }

    return 0;
}

