#include <queue.h>
#include <stdint.h>
#include "skel.h"

// argv[1] = tabela de routare
struct route_table_entry {
// o intrare a tabelei de routare  
    uint32_t prefix;
    uint32_t next_hop;
    uint32_t mask;
// adrese IP
    int interface;
} __attribute__((packed));

struct arp_entry {
    __u32 ip;
    uint8_t mac[6];
};

struct route_table_entry *get_best_route(struct route_table_entry *rtable, __u32 dest_ip, int l, int r) {
// realizeaza cautarea in tabela de routare folosind cautare binara
// in afara de ultimele 5 randuri, prefixele din tabela
// sunt ordonate crescator dupa valoarea in decimal
// in afara de ultimul rand, toate mastile sunt identice (255.255.255.0)

    if (dest_ip == rtable[64264].prefix) {
        // cautare in ultimul rand al tabelei
        return &rtable[64264];
    }

    // acum caut in ultimele 5 randuri ale tabelei (fara ultimul rand)
    for (int i = 0; i < 4; i++) {
        if ((dest_ip & rtable[i + 64260].mask) == rtable[i + 64260].prefix) {
            return &rtable[i + 64260];
        }
    }

    if (r >= l) {
        int mid = l + (r - l) / 2;
      if ((dest_ip & rtable[mid].mask) == rtable[mid].prefix)
            return &rtable[mid];
        if ((dest_ip & rtable[mid].mask) < rtable[mid].prefix)
            return get_best_route(rtable, dest_ip, l, mid - 1);
        return get_best_route(rtable, dest_ip, mid + 1, r);
    }

return NULL;
}

struct arp_entry *get_arp_entry(__u32 ip, struct arp_entry *arp_table) {
// gaseste adresa Mac corespunzatoare acestei adresei IP
    
    for (int i = 0; i < 64265; i++) {
        if (ip == arp_table[i].ip) {
            return &arp_table[i];
        }
    }

return NULL;
}

int main(int argc, char *argv[]) {
        
    packet m;
    // payload--> 1600 caractere + len + interface
    int rc;
    queue q = queue_create();
    // coada de asteptare pentru pachete
    init(argc - 2, argv + 2);
    
    struct route_table_entry *rtable = malloc(sizeof(struct route_table_entry) * 64265);            
    // vector de elemente de tipul "route_table_entry" = tabela de routare
    struct arp_entry *arp_table = malloc(sizeof(struct arp_entry) * 64265);
    // vector de elemente de tip "arp_entry" = tabela arp
    FILE *file = fopen(argv[1], "r");
    char *line = NULL;
    size_t len = 0;
    int index = 0;
    int arp_index = 0;

    while (getline(&line, &len, file) != -1) {
        char* token = strtok(line, " \n");
        struct in_addr prefix;
        inet_aton(token, &prefix);
        rtable[index].prefix = prefix.s_addr;
    		token = strtok(NULL, " \n");
        struct in_addr next_hop;
        inet_aton(token, &next_hop);
        rtable[index].next_hop = next_hop.s_addr;
        token = strtok(NULL, " \n");
        struct in_addr mask;
        inet_aton(token, &mask);
        rtable[index].mask = mask.s_addr;
        token = strtok(NULL, " \n");
        rtable[index].interface = atoi(token);
        index++;
    }
    fclose(file);
    // pana aici am realizat parsarea tabelei de routare

    int a = 0;
    // seq number pentru pachetele noi create

    while (1) {
        rc = get_packet(&m);
        // intoarce "0" in caz de eroare
        DIE(rc < 0, "get_message");

				// se extrage header-ul Ethernet
        struct ether_header *eth_hdr = (struct ether_header *) m.payload;
        if (eth_hdr == NULL) {
            printf("Eroare la extragerea header-ului ETHERNET\n");
            continue;
        }
    
        uint16_t protocol_pachet = eth_hdr->ether_type;
        // verific daca este un pachet IP
        if (ntohs(protocol_pachet) == ETHERTYPE_IP) {
            // se extrage header-ul IP
            struct iphdr *ip_hdr = (struct iphdr *)(m.payload + sizeof(struct ether_header));
            if (ip_hdr == NULL) {
                printf("Eroare la extragerea header-ului IP\n");
                continue;
            }
            // verific daca este destinat router-ului
            __u32 dest_ip = ip_hdr->daddr;
            struct in_addr interface_ip;
            inet_aton(get_interface_ip(m.interface), &interface_ip);
            if (interface_ip.s_addr == dest_ip) {
                // verific daca este un pachet icmp
                if (ip_hdr->protocol == 1) {
                    // se extrage header-ul ICMP
                    struct icmphdr *icmp_hdr = parse_icmp(m.payload);
                    if (icmp_hdr == NULL) {
                        continue;
                    }
                    // verific daca este un pachet de tip  ECHO request
                    if (icmp_hdr->type == 8) {
                        // raspund cu un echo replay
                        send_icmp(ip_hdr->daddr, ip_hdr->saddr, eth_hdr->ether_shost,
                                 eth_hdr->ether_dhost, 0, icmp_hdr->code, m.interface,
                                 htons(getpid() & 0xFFFF), a);
                        a++;
                        continue;
                    }
                    else {
                        // dau drop la pachet
                        continue;
                    }
                }
                else {
                // daca este un pachet de tip Ip, dar nu Icmp, destinat routerului  
                    continue;
                }
            }
        }
    
        // daca este un pachet de tip arp
        if (ntohs(protocol_pachet) == ETHERTYPE_ARP) {
            // extrag header-ul arp
            struct arp_header *arp_hdr = parse_arp(m.payload);
            if (arp_hdr == NULL) {
                printf("Eroare la extragerea header-ului ARP\n");
                continue;
            }  
            // daca este un pachet de tip ARP request
            if (ntohs(arp_hdr->op) == 1) {
							// trimit un arp reply 
							eth_hdr->ether_type = 0x0608;
							// setez tipul astfel incat sa fie pachet de tip ARP 
							for (int i = 0; i < 6; i++) {
								eth_hdr->ether_dhost[i] = eth_hdr->ether_shost[i];
							}
							// destinatia este mac-ul hostului care a dat request
							get_interface_mac(m.interface, eth_hdr->ether_shost);
							// sursa este mac-ul routerului
							send_arp(arp_hdr->spa, arp_hdr->tpa, eth_hdr, m.interface, htons(ARPOP_REPLY));
							continue;
            }
            else if (ntohs(arp_hdr->op) == 2) {
                // daca este un pachet de tip ARP reply
                // extrag adresa mac sursa din reply
                // si o pun in tabela alaturi de adresa ip sursa
                arp_table[arp_index].ip = arp_hdr->spa;
                for (int i = 0; i < 6; i++) {
                    arp_table[arp_index].mac[i] = arp_hdr->sha[i];
                }
                arp_index++;
                // scot pachetul din coada
                packet* pack = malloc(sizeof(packet));
                if (queue_empty(q) != 1) {
								// daca exista pachete in coada 
									pack = queue_deq(q);
                	struct ether_header *eth_hdr2 = (struct ether_header *) pack->payload;
                	// completez header-ul ethernet- setez ca destinatie adresa mac a router-ului
									get_interface_mac(pack->interface, eth_hdr2->ether_shost);
                	for (int i = 0; i < 6; i++) {
                   	 eth_hdr2->ether_dhost[i] = arp_hdr->sha[i];
                	}
                	send_packet(pack->interface, pack);
									// trimit pachetul catre next_hop 
                }
                continue;
            }
        }
        
        if (ntohs(protocol_pachet) == ETHERTYPE_IP) {
            // se extrage header-ul IP
            struct iphdr *ip_hdr = (struct iphdr *)(m.payload + sizeof(struct ether_header));
            if (ip_hdr == NULL) {
                printf("Eroare la extragerea header-ului IP\n");
                continue;
            }
            // daca este un pachet ip nedestinat routerului
            // (poate fi icmp sau doar IP fara a fi icmp)
            // verific ttl-ul
            if (ip_hdr->ttl <= 1) {
                 // trimit un mesaj icmp de time exceeded
                ip_hdr->protocol = 1;
                send_icmp_error(ip_hdr->saddr, inet_addr(get_interface_ip(m.interface)),
                         eth_hdr->ether_dhost, eth_hdr->ether_shost, 11, 0, m.interface);
                // drop la pachet
                continue;
            }
            else {
            // ttl corect, verific checksum-ul
                __u16 old_checksum = ip_hdr->check;
                ip_hdr->check = 0;
                __u16 new_check = ip_checksum(ip_hdr, sizeof(struct iphdr));
                if (new_check != old_checksum) {
                     // drop la pachet
                    continue;
                }
                else {
                // checksum corect --> decrementeaza ttl, updateaza checksum
                    ip_hdr->ttl--;
                    ip_hdr->check = 0;
                    __u16 new_checksum = ip_checksum(ip_hdr, sizeof(struct iphdr));
                    ip_hdr->check = new_checksum;
                    struct route_table_entry *route = malloc(sizeof(struct route_table_entry));
                    route = get_best_route(rtable, ip_hdr->daddr, 0, 64259);
                    // am gasit intrarea potrivita din tabela de routare
                    if (route == NULL) {
                        // trimit un ICMP Destination Unreachable
                        ip_hdr->protocol = 1;
                        send_icmp_error(ip_hdr->saddr, inet_addr(get_interface_ip(m.interface)),
                            eth_hdr->ether_dhost, eth_hdr->ether_shost, 3, 0, m.interface);
                        continue;
                    }
                    else {
                        struct arp_entry * arp = malloc(sizeof(struct arp_entry));
                        arp = get_arp_entry(route->next_hop, arp_table);
                        // caut adresa mac corespunzatoare in tabela arp
                        if (arp == NULL) {
                            // adresa Mac nu este cunoscuta local, deci trimit un arp request
														get_interface_mac(route->interface, eth_hdr->ether_shost);
                            uint8_t broadcast_addr[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
                            for (int j = 0; j < 6; j++) {
                                eth_hdr->ether_dhost[j] = broadcast_addr[j];
                            }        
                            eth_hdr->ether_type = 0x0608;
                            send_arp(route->next_hop, inet_addr(get_interface_ip(route->interface)),
                                         eth_hdr, route->interface, htons(ARPOP_REQUEST));
														// trimitere request 
                            packet *p = malloc(sizeof(packet));
                            memcpy(p, &m, sizeof(packet));
                            p->interface = route->interface;    
														// introduc pachetul in coada de asteptare pana se afla mac-ul next_hop-ului                 
                            queue_enq(q, p);
                            continue;
                        }
                        else {
                            // updatare mac sursa si mac destinatie
                            for (int l = 0; l < 6; l++) {
                                eth_hdr->ether_dhost[l] = arp->mac[l];
                            }
                            get_interface_mac(route->interface, eth_hdr->ether_shost);
                            send_packet(route->interface, &m);
                        }
                    }
                }
            }
        }  
    }
}


