#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <pcap.h>
#include <net/if.h>
#include <linux/if_packet.h>
#include <sys/ioctl.h>

// Define the network interface and pcap file
#define INTERFACE "eth0"
#define PCAP_FILE "0.pcap"

void process_packet(const u_char *packet, struct pcap_pkthdr *header);
int count = 0 ;

int main() {
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];

    // Open the pcap file for reading
    handle = pcap_open_offline(PCAP_FILE, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Error opening pcap file: %s\n", errbuf);
        return 1;
    }

    // Create a raw socket for sending packets
    int raw_socket = socket(AF_PACKET, SOCK_RAW, IPPROTO_RAW);
    if (raw_socket == -1) {
        perror("Socket creation error");
        return 1;
    }

    // Set the network interface for sending packets
    struct sockaddr_ll socket_address;
    struct ifreq ifr;
    memset(&socket_address, 0, sizeof(socket_address));
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, INTERFACE, IFNAMSIZ - 1);

    if (ioctl(raw_socket, SIOCGIFINDEX, &ifr) == -1) {
        perror("ioctl");
        return 1;
    }

    socket_address.sll_family = AF_PACKET;
    socket_address.sll_protocol = htons(ETH_P_ALL);
    socket_address.sll_ifindex = ifr.ifr_ifindex;

    while (1) {
        struct pcap_pkthdr header;
        const u_char *packet = pcap_next(handle, &header);

        if (packet == NULL) {
            break; // End of file
        }

        // Process and send the packet
        process_packet(packet, &header);
        sendto(raw_socket, packet, header.len, 0, (struct sockaddr *)&socket_address, sizeof(socket_address));
    }
	
    // Close the pcap file and socket
    pcap_close(handle);
    close(raw_socket);
    printf("total packets recieved ");
    printf("%d",count);
    return 0;
}

void process_packet(const u_char *packet, struct pcap_pkthdr *header) {
    struct ip *ipHeader = (struct ip *)(packet + 14); // Skip Ethernet header
    struct tcphdr *tcpHeader = (struct tcphdr *)(packet + 14 + (ipHeader->ip_hl << 2)); // Skip IP header

    // Extract source and destination IP addresses
    char sourceIP[INET_ADDRSTRLEN];
    char destIP[INET_ADDRSTRLEN];

    inet_ntop(AF_INET, &(ipHeader->ip_src), sourceIP, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(ipHeader->ip_dst), destIP, INET_ADDRSTRLEN);

    // Extract source and destination ports
    unsigned int sourcePort = ntohs(tcpHeader->th_sport);
    unsigned int destPort = ntohs(tcpHeader->th_dport);

    // Print information about the TCP flow
    printf("Source IP: %s\n", sourceIP);
    printf("Source Port: %u\n", sourcePort);
    printf("Dest IP: %s\n", destIP);
    printf("Dest Port: %u\n", destPort);
    printf("\n");
    count++;
}

