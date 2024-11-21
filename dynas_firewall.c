#ifndef HEADER_FILE_NAME_H
#define HEADER_FILE_NAME_H
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <netinet/ip.h>  // Define struct iphdr
#include <netinet/tcp.h> // Define struct tcphdr
#include <netinet/udp.h> // Define struct udphdr
#include <arpa/inet.h>   // Funções para manipulação de IPs
#include <linux/netfilter.h>
#endif

#define CONFIG_FILE "firewall_rules.conf"
#define LOG_FILE "/var/log/firewall.log"
#define MAX_RULES 100


// Estrutura para armazenar regras
typedef struct {
    char src_ip[40];
    char dst_ip[40];
    int src_port;
    int dst_port;
    char protocol[8];
    int action; // 0: DROP, 1: ACCEPT
    char start_time[6]; // Hora de início (HH:MM)
    char end_time[6];   // Hora de fim (HH:MM)
} Rule;

Rule rules[MAX_RULES];
int rule_count = 0;

// Estatísticas
int packets_blocked = 0;
int packets_accepted = 0;

// Função para carregar regras do arquivo
void load_rules() {
    FILE *config = fopen(CONFIG_FILE, "r");
    if (!config) {
        perror("Erro ao abrir arquivo de configuração");
        return;
    }

    rule_count = 0;
    while (fscanf(config, "%39s %39s %d %d %7s %d %5s %5s",
                  rules[rule_count].src_ip, rules[rule_count].dst_ip,
                  &rules[rule_count].src_port, &rules[rule_count].dst_port,
                  rules[rule_count].protocol, &rules[rule_count].action,
                  rules[rule_count].start_time, rules[rule_count].end_time) != EOF) {
        rule_count++;
        if (rule_count >= MAX_RULES) {
            fprintf(stderr, "Número máximo de regras excedido\n");
            break;
        }
    }
    fclose(config);
    printf("Regras carregadas: %d\n", rule_count);
}

// Função para registrar logs
void log_blocked_packet(const char *src_ip, const char *dst_ip, const char *protocol, int src_port, int dst_port) {
    FILE *log_file = fopen("/var/log/firewall.log", "a");
if (log_file) {
    fprintf(log_file, "Blocked packet: Src=%s, Dst=%s, Protocol=%s\n", src_ip, dst_ip, protocol);
    fclose(log_file);
}

printf("Blocked packet: Src=%s, Dst=%s, Protocol=%s, SrcPort=%d, DstPort=%d\n",
       src_ip, dst_ip, protocol, src_port, dst_port);


}

void save_statistics() {
    FILE *file = fopen("firewall_stats.dat", "w");
    if (file) {
        fprintf(file, "%d %d\n", packets_blocked, packets_accepted);
        fclose(file);
    } else {
        perror("Erro ao salvar estatísticas");
    }
}

void load_statistics() {
    FILE *file = fopen("firewall_stats.dat", "r");
    if (file) {
        fscanf(file, "%d %d", &packets_blocked, &packets_accepted);
        fclose(file);
    } else {
        packets_blocked = 0;
        packets_accepted = 0;
    }
}


// Função para verificar regras
int check_rules(const char *src_ip, const char *dst_ip, int src_port, int dst_port, const char *protocol) {
    time_t now = time(NULL);
    struct tm *local_time = localtime(&now);
    char current_time[6];
    snprintf(current_time, sizeof(current_time), "%02d:%02d", local_time->tm_hour, local_time->tm_min);

    for (int i = 0; i < rule_count; i++) {
        if ((strcmp(rules[i].src_ip, "*") == 0 || strcmp(rules[i].src_ip, src_ip) == 0) &&
            (strcmp(rules[i].dst_ip, "*") == 0 || strcmp(rules[i].dst_ip, dst_ip) == 0) &&
            (rules[i].src_port == 0 || rules[i].src_port == src_port) &&
            (rules[i].dst_port == 0 || rules[i].dst_port == dst_port) &&
            (strcmp(rules[i].protocol, "*") == 0 || strcmp(rules[i].protocol, protocol) == 0) &&
            (strcmp(current_time, rules[i].start_time) >= 0 && strcmp(current_time, rules[i].end_time) <= 0)) {
            return rules[i].action;
        }
        printf("Comparando pacote: Src=%s, Dst=%s, SrcPort=%d, DstPort=%d, Protocol=%s\n",
        src_ip, dst_ip, src_port, dst_port, protocol);
        printf("Regra atual: Src=%s, Dst=%s, SrcPort=%d, DstPort=%d, Protocol=%s, Action=%d\n",
        rules[i].src_ip, rules[i].dst_ip, rules[i].src_port, rules[i].dst_port,
        rules[i].protocol, rules[i].action);

    }
    return 1; // Default: ACCEPT
}

// Função de callback para processar pacotes
static int process_packet(struct nfq_q_handle *queue_handle, struct nfgenmsg *msg,
                          struct nfq_data *packet_data, void *data) {
    unsigned char *packet;
    struct nfqnl_msg_packet_hdr *ph;
    int id = 0;

    ph = nfq_get_msg_packet_hdr(packet_data);
    if (ph) {
        id = ntohl(ph->packet_id);
    }

    struct tcphdr {
        uint16_t source;  // Porta de origem
        uint16_t dest;    // Porta de destino
        uint32_t seq;     // Número de sequência
        uint32_t ack_seq; // Número de confirmação
        uint16_t res1 : 4, doff : 4, fin : 1, syn : 1, rst : 1, psh : 1, ack : 1, urg : 1, res2 : 2;
        uint16_t window;  // Tamanho da janela
        uint16_t check;   // Soma de verificação
        uint16_t urg_ptr; // Ponteiro urgente
    };


    int packet_len = nfq_get_payload(packet_data, &packet);
    if (packet_len >= 0) {
        struct iphdr *ip_header = (struct iphdr *)packet;
        char src_ip[40], dst_ip[40];
        inet_ntop(AF_INET, &ip_header->saddr, src_ip, sizeof(src_ip));
        inet_ntop(AF_INET, &ip_header->daddr, dst_ip, sizeof(dst_ip));

        char protocol[8] = "OTHER";
        int src_port = 0, dst_port = 0;

        if (ip_header->protocol == IPPROTO_TCP) {
            strcpy(protocol, "TCP");
            struct tcphdr *tcp_header = (struct tcphdr *)(packet + ip_header->ihl * 4);
            src_port = ntohs(tcp_header->source);
            dst_port = ntohs(tcp_header->dest);
        } else if (ip_header->protocol == IPPROTO_UDP) {
                strcpy(protocol, "UDP");
                struct udphdr *udp_header = (struct udphdr *)(packet + ip_header->ihl * 4);
                src_port = ntohs(udp_header->source);
                dst_port = ntohs(udp_header->dest);
            } else {
                strcpy(protocol, "OTHER");
            }


        printf("Processing packet: Src=%s, Dst=%s, Protocol=%s, SrcPort=%d, DstPort=%d\n",
               src_ip, dst_ip, protocol, src_port, dst_port);

        int action = check_rules(src_ip, dst_ip, src_port, dst_port, protocol);
        if (action == 0) { // DROP
            log_blocked_packet(src_ip, dst_ip, protocol, src_port, dst_port);
            packets_blocked++;
            printf("Packet blocked. Total blocked: %d\n", packets_blocked);
            return nfq_set_verdict(queue_handle, id, NF_DROP, 0, NULL);
        }
        packets_accepted++;
        printf("Packet accepted. Total accepted: %d\n", packets_accepted);
    }

    return nfq_set_verdict(queue_handle, id, NF_ACCEPT, 0, NULL);
}

#include <signal.h>

void handle_sigint(int sig) {
    save_statistics();
    printf("\nFirewall interrompido.\n");
    printf("Pacotes bloqueados: %d\n", packets_blocked);
    printf("Pacotes aceitos: %d\n", packets_accepted);
    exit(0);
}


int main() {
    struct nfq_handle *handle;
    struct nfq_q_handle *queue_handle;

    signal(SIGINT, handle_sigint); // Função para capturar Ctrl+C

    printf("Inicializando firewall...\n");

    load_statistics(); // Carregar estatísticas salvas
    load_rules();

    handle = nfq_open();
    if (!handle) {
        perror("Erro ao abrir Netfilter");
        exit(EXIT_FAILURE);
    }

    if (nfq_unbind_pf(handle, AF_INET) < 0 || nfq_bind_pf(handle, AF_INET) < 0) {
        perror("Erro ao configurar Netfilter");
        nfq_close(handle);
        exit(EXIT_FAILURE);
    }

    queue_handle = nfq_create_queue(handle, 0, &process_packet, NULL);
    if (!queue_handle) {
        perror("Erro ao criar fila");
        nfq_close(handle);
        exit(EXIT_FAILURE);
    }

    if (nfq_set_mode(queue_handle, NFQNL_COPY_PACKET, 0xffff) < 0) {
        perror("Erro ao configurar modo de cópia");
        nfq_destroy_queue(queue_handle);
        nfq_close(handle);
        exit(EXIT_FAILURE);
    }

    printf("Firewall ativo.\n");

    char buf[4096] __attribute__((aligned));
    int rv;
    while ((rv = recv(nfq_fd(handle), buf, sizeof(buf), 0)) > 0) {
        nfq_handle_packet(handle, buf, rv);
    }

    nfq_destroy_queue(queue_handle);
    nfq_close(handle);

    save_statistics(); // Salvar estatísticas antes de sair

    return 0;
}

