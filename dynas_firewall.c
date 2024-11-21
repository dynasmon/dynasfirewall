#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <netinet/ip.h>       // Para cabeçalhos IP
#include <netinet/tcp.h>      // Para cabeçalhos TCP
#include <netinet/udp.h>      // Para cabeçalhos UDP
#include <arpa/inet.h>        // Para funções de conversão de endereços IP
#include <linux/netfilter.h>  // Para macros NF_DROP e NF_ACCEPT


#define CONFIG_FILE "firewall_rules.conf"
#define LOG_FILE "/var/log/firewall.log"

// Estrutura para armazenar regras dinâmicas
typedef struct {
    char src_ip[16];
    char dst_ip[16];
    int src_port;
    int dst_port;
    char protocol[8];
    int action; // 0: DROP, 1: ACCEPT
} Rule;

// Lista de regras dinâmicas
#define MAX_RULES 100
Rule rules[MAX_RULES];
int rule_count = 0;

// Função para carregar regras do arquivo
void load_rules() {
    FILE *config = fopen(CONFIG_FILE, "r");
    if (!config) {
        perror("Erro ao abrir arquivo de configuração");
        return;
    }

    rule_count = 0;
    while (fscanf(config, "%15s %15s %d %d %7s %d",
                  rules[rule_count].src_ip, rules[rule_count].dst_ip,
                  &rules[rule_count].src_port, &rules[rule_count].dst_port,
                  rules[rule_count].protocol, &rules[rule_count].action) != EOF) {
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
    FILE *log_file = fopen(LOG_FILE, "a");
    if (!log_file) {
        perror("Erro ao abrir arquivo de log");
        return;
    }
    fprintf(log_file, "Bloqueado: Src=%s:%d Dst=%s:%d Protocol=%s\n", src_ip, src_port, dst_ip, dst_port, protocol);
    fclose(log_file);
}

// Função para verificar regras
int check_rules(const char *src_ip, const char *dst_ip, int src_port, int dst_port, const char *protocol) {
    for (int i = 0; i < rule_count; i++) {
        if ((strcmp(rules[i].src_ip, "*") == 0 || strcmp(rules[i].src_ip, src_ip) == 0) &&
            (strcmp(rules[i].dst_ip, "*") == 0 || strcmp(rules[i].dst_ip, dst_ip) == 0) &&
            (rules[i].src_port == 0 || rules[i].src_port == src_port) &&
            (rules[i].dst_port == 0 || rules[i].dst_port == dst_port) &&
            (strcmp(rules[i].protocol, "*") == 0 || strcmp(rules[i].protocol, protocol) == 0)) {
            return rules[i].action;
        }
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

    int packet_len = nfq_get_payload(packet_data, &packet);
    if (packet_len >= 0) {
        struct iphdr *ip_header = (struct iphdr *)packet;
        char src_ip[16], dst_ip[16];
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
        } else if (ip_header->protocol == IPPROTO_ICMP) {
            strcpy(protocol, "ICMP");
        }

        int action = check_rules(src_ip, dst_ip, src_port, dst_port, protocol);
        if (action == 0) { // DROP
            log_blocked_packet(src_ip, dst_ip, protocol, src_port, dst_port);
            return nfq_set_verdict(queue_handle, id, NF_DROP, 0, NULL);
        }
    }

    return nfq_set_verdict(queue_handle, id, NF_ACCEPT, 0, NULL);
}

int main() {
    struct nfq_handle *handle;
    struct nfq_q_handle *queue_handle;

    printf("Inicializando firewall...\n");

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

    return 0;
}
