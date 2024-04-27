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
#define KEY_FILE "bf_key.bin"

int crypto = 0;
unsigned char* session_key;
size_t session_key_len;


void generate_session_key(int *sock) {

    DH *privkey;
    int codes;

    printf("Generating session key with DH algorithm...\n");

    /* Create the encryption context */
    if(NULL == (privkey = DH_new())) {
        fprintf(stderr, "Error for initialize DH\n");
        exit(-1);
    }

    /* Generate parameters */

    BIGNUM *prime = BN_new();
    BIGNUM *g = BN_new();

    if (DH_generate_parameters_ex(privkey, 1024, DH_GENERATOR_2, 0) != 1) {
        return;
    }

    while (1 != DH_check(privkey, &codes)) {
        DH_generate_parameters_ex(privkey, 1024, DH_GENERATOR_2, 0);
    }

    DH_get0_pqg(privkey,&prime, NULL, &g);

    char *prime_str = BN_bn2hex(prime);
    char *g_str = BN_bn2hex(g);

    send(*sock, prime_str, strlen(prime_str), 0);
    send(*sock, g_str, strlen(g_str), 0);

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

// get sockaddr, IPv4 or IPv6:
void *get_in_addr(struct sockaddr *sa)
{
    if (sa->sa_family == AF_INET) {
		        return &(((struct sockaddr_in*)sa)->sin_addr);
    }

    return &(((struct sockaddr_in6*)sa)->sin6_addr);
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

    char* port = argv[1];
    char* c = argv[2];

    crypto = atoi(c);

    if (crypto == 0) {

        printf("Server's working in mode without encryption\n");

    } else if (crypto == 1) {

        printf("Server's working with encryption mode, session key is stored in file\n");

    } else if (crypto == 2) {

        printf("Server's working with encryption mode, session key is generating with dh\n");

    } else {
        perror("Unknown server mode");
        exit(-1);
    }


    int port_int = atoi(port);

    struct sockaddr_in addr;
    int yes = 1;

    // Listener socker for 0.0.0.0 with port from parametres
    int listener = socket(AF_INET, SOCK_STREAM, 0);

    if (listener < 0) {
        perror("Failed to create listener socket");
        exit(-1);
    }

    addr.sin_family = AF_INET;
    addr.sin_port = htons(port_int);
    addr.sin_addr.s_addr = htonl(INADDR_ANY);

    // Release listener
    setsockopt(listener, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int));

    // bind listener for external connections
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

        // Waiting and accepting client
        client_sock = accept(listener, (struct sockaddr *)&remoteaddr, &addrlen);
        if (client_sock == -1)
        {
            perror("accept");
            continue;
        }

        // Get information about client
        char remoteIP[INET6_ADDRSTRLEN];
        inet_ntop(remoteaddr.ss_family, get_in_addr((struct sockaddr *)&remoteaddr), remoteIP, sizeof(remoteIP));

	printf("Connection established with %s\n", remoteIP);

        //Close listener, work with only one client
        close(listener);

        // Send info about encryption to client
        int crypto_info = htonl(crypto);
    	if (send(client_sock, &crypto_info, sizeof(crypto_info), 0) < 0) {
            perror("Error in sending data to client");
            exit(-1);
        }

        break;
    }

    // Generetion key for crypto mode
    if (crypto == 1) {
        session_key = malloc(16);
        session_key_len = 16;
        FILE *key_file = fopen(KEY_FILE, "rb");

        if (key_file == NULL) return -1;

        if (fread(session_key, 16, 1, key_file) != 1)
        {
            fclose(key_file);
            return -1;
        }

        fclose(key_file);
    } else if (crypto == 2) {
    	generate_session_key(&client_sock);
    	printf("Encryption key has been successfully generated\n");
    }

    fd_set read_fds;

    FD_ZERO(&read_fds);
    FD_SET(client_sock, &read_fds);
    FD_SET(STDIN_FILENO, &read_fds);

    int max_fd = (client_sock > STDIN_FILENO) ? client_sock : STDIN_FILENO;

    while (1) {
        fd_set temp_fds = read_fds;

        // Waiting activity from stdin or client socket, select provides duplex communication
        int activity = select(max_fd + 1, &temp_fds, NULL, NULL, NULL);
        if (activity < 0) {
            perror("Error in select");
            exit(EXIT_FAILURE);
        }

        // Check message from client
        if (FD_ISSET(client_sock, &temp_fds)) {
            if (! recv_message(&client_sock)) {
                close(client_sock);
                break;
            }
        }

        // Check stdin to sending message for client
        if (FD_ISSET(STDIN_FILENO, &temp_fds)) {
            send_message(&client_sock);
        }

    }

    return 0;
}

