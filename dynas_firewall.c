#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <pthread.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <linux/netfilter.h>

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

// Variáveis globais
int packets_blocked = 0;
int packets_accepted = 0;
int rule_count = 0;
int firewall_running = 1; // Flag para indicar o estado do firewall
Rule rules[MAX_RULES];

// Declarações de funções
void load_rules();
void save_statistics();
void load_statistics();
void log_blocked_packet(const char *src_ip, const char *dst_ip, const char *protocol, int src_port, int dst_port);
void handle_sigint(int sig);
void *interactive_menu(void *arg);
int check_rules(const char *src_ip, const char *dst_ip, int src_port, int dst_port, const char *protocol);
static int process_packet(struct nfq_q_handle *queue_handle, struct nfgenmsg *msg, struct nfq_data *packet_data, void *data);

// Implementações de funções
void load_statistics() {
    FILE *file = fopen("firewall_stats.dat", "r");
    if (file) {
        fscanf(file, "%d %d", &packets_blocked, &packets_accepted);
        fclose(file);
    }
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

// Implementação do menu interativo
void *interactive_menu(void *arg) {
    char option;
    while (1) {
        printf("\n--- Firewall Menu ---\n");
        printf("1. Ver estatísticas\n");
        printf("2. Adicionar regra\n");
        printf("3. Listar regras\n");
        printf("4. Parar firewall\n");
        printf("5. Retomar firewall\n");
        printf("6. Sair\n");
        printf("Escolha uma opção: ");
        scanf(" %c", &option);

        switch (option) {
            case '1':
                printf("\n--- Estatísticas ---\n");
                printf("Pacotes bloqueados: %d\n", packets_blocked);
                printf("Pacotes aceitos: %d\n", packets_accepted);
                break;

            case '2': {
                Rule new_rule;
                printf("\n--- Adicionar Regra ---\n");
                printf("IP de origem (use * para qualquer): ");
                scanf("%39s", new_rule.src_ip);
                printf("IP de destino (use * para qualquer): ");
                scanf("%39s", new_rule.dst_ip);
                printf("Porta de origem (0 para qualquer): ");
                scanf("%d", &new_rule.src_port);
                printf("Porta de destino (0 para qualquer): ");
                scanf("%d", &new_rule.dst_port);
                printf("Protocolo (TCP, UDP ou *): ");
                scanf("%7s", new_rule.protocol);
                printf("Ação (0: DROP, 1: ACCEPT): ");
                scanf("%d", &new_rule.action);
                printf("Hora de início (HH:MM): ");
                scanf("%5s", new_rule.start_time);
                printf("Hora de término (HH:MM): ");
                scanf("%5s", new_rule.end_time);

                if (rule_count < MAX_RULES) {
                    rules[rule_count++] = new_rule;
                    printf("Regra adicionada com sucesso.\n");
                } else {
                    printf("Número máximo de regras atingido.\n");
                }
                break;
            }

            case '3':
                printf("\n--- Regras Atuais ---\n");
                for (int i = 0; i < rule_count; i++) {
                    printf("%d. Src: %s, Dst: %s, SrcPort: %d, DstPort: %d, Protocol: %s, Action: %s, Time: %s-%s\n",
                           i + 1, rules[i].src_ip, rules[i].dst_ip, rules[i].src_port, rules[i].dst_port,
                           rules[i].protocol, rules[i].action ? "ACCEPT" : "DROP", rules[i].start_time, rules[i].end_time);
                }
                break;

            case '4':
                firewall_running = 0;
                printf("Firewall pausado.\n");
                break;

            case '5':
                firewall_running = 1;
                printf("Firewall retomado.\n");
                break;

            case '6':
                printf("Encerrando o firewall...\n");
                save_statistics();
                exit(0);

            default:
                printf("Opção inválida. Tente novamente.\n");
                break;
        }
    }
    return NULL;
}

static int process_packet(struct nfq_q_handle *queue_handle, struct nfgenmsg *msg,
                          struct nfq_data *packet_data, void *data) {
    unsigned char *packet;
    struct nfqnl_msg_packet_hdr *ph;
    int id = 0;

    ph = nfq_get_msg_packet_hdr(packet_data);
    if (ph) {
        id = ntohl(ph->packet_id);
    }

    struct iphdr *ip_header = (struct iphdr *)packet;
    char src_ip[40], dst_ip[40];
    inet_ntop(AF_INET, &ip_header->saddr, src_ip, sizeof(src_ip));
    inet_ntop(AF_INET, &ip_header->daddr, dst_ip, sizeof(dst_ip));

    int action = check_rules(src_ip, dst_ip, 0, 0, "TCP"); // Exemplo básico
    return nfq_set_verdict(queue_handle, id, action == 0 ? NF_DROP : NF_ACCEPT, 0, NULL);
}

void handle_sigint(int sig) {
    save_statistics();
    printf("\nFirewall interrompido.\n");
    printf("Pacotes bloqueados: %d\n", packets_blocked);
    printf("Pacotes aceitos: %d\n", packets_accepted);
    exit(0);
}

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


// Função principal
int main() {
    struct nfq_handle *handle;
    struct nfq_q_handle *queue_handle;
    pthread_t menu_thread;

    signal(SIGINT, handle_sigint); // Captura Ctrl+C

    printf("Inicializando firewall...\n");

    load_statistics();
    load_rules();

    if (pthread_create(&menu_thread, NULL, interactive_menu, NULL) != 0) {
        perror("Erro ao criar thread do menu");
        return EXIT_FAILURE;
    }

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

    save_statistics();
    pthread_join(menu_thread, NULL);
    return 0;
}
