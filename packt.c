/*
packt.c
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <errno.h>
#include <netdb.h>
#include <net/if.h>
#include <unistd.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <net/ethernet.h>
#include <sys/socket.h>

#define PACKT_VERSION "0.0.1"
void check_packet_header(unsigned char *, int);
void print_ethernet_header(unsigned char*, int);
void ip_packet_header(unsigned char *, int);
void tcp_packet_header(unsigned char *, int);
void udp_packet_header(unsigned char *, int);
void icmp_packet_header(unsigned char *, int);
void print_packet_data(unsigned char*, int);


const char *white = "\033[1;37m",
//*grey = "\033[0;37m",
//*purple = "\033[0;35m",
*red = "\033[0;31m",
*green = "\033[0;32m",
*yellow = "\033[0;33m",
*cyan = "\033[0;36m",
//*cafe = "\033[0;33m",
//*fiuscha = "\033[0;35m",
*blue = "\033[1;34m",
*reset = "\e[0m";

void print_help() {
    const char *help = 
    "Usage: packt [OPTIONS] <args>\n"
    "Version 0.0.1\n"
    "  -h, --help                  Print this help message and exit.\n"
    "  -i --interface              Specify the interface to sniff packets on.\n"
    "  -w --write                  Specify a file name to save all captured packets.\n"
    "By default packt will sniff all types of packets, but the following options are also available.\n"
    "SNIFFING OPTIONS:\n"
    "  --tcp                       Sniff TCP packets only.\n"
    "  --udp                       Sniff UDP packets only.\n"
    "  --icmp                      Sniff ICMP packets only.\n"
    "  --all                       Sniff all packets, this is the default options.\n"
    "\nGitHub: https://github.com/4anonz/packt\n";

    printf("%s\n", help);
    exit(0);
}

FILE *fp = NULL;
int tcp = 0, udp = 0, icmp = 0, igmp = 0, total = 0, others = 0;

int main(int argc, char *argv[]) {

    int raw_socket;

    char *interface = 0; int proto = -1;
    char *file_name = 0;
    for(int i = 0; i < argc; i++) {
        if(strcmp("-i", argv[i]) == 0 || strcmp("--interface", argv[i]) == 0) {
            if(!argv[i+1])
                print_help();
            interface = argv[i+1];
        }
        if(strcmp("--tcp", argv[i]) == 0)
            proto = IPPROTO_TCP;
        if(strcmp("--udp", argv[i]) == 0)
            proto = IPPROTO_UDP;
        if(strcmp("--icmp", argv[i]) == 0)
            proto = IPPROTO_ICMP;
        if(strcmp("-w", argv[i]) == 0 || strcmp("--write", argv[i]) == 0) {
            if(!argv[i+1])
                print_help();
            file_name = argv[i+1]; 
        }
        if(strcmp("-h", argv[i]) == 0 || strcmp("--help", argv[i]) == 0)
            print_help();

    }

    printf("%s|--[*]%s Starting Network Packet Sniffer....\n", blue, reset);
    printf("%s|--[*]%s Creating raw socket...", blue, reset);
    switch(proto) {
        case IPPROTO_TCP:
            raw_socket = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
            break;
        case IPPROTO_UDP:
            raw_socket = socket(AF_INET, SOCK_RAW, IPPROTO_UDP);
            break;
        case IPPROTO_ICMP:
            raw_socket = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
            break;
        default:
            raw_socket = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
            break;
    }

    if(raw_socket < 0) {

        fprintf(stderr, "%s|--[!]%s Failed to create raw socket %s Make sure to run this program as root.!!\n", blue, reset, strerror(errno));
        return 1;
    }
    printf("Done\n");

    /**
     * If interface is specified, then make the socket bind to that
     * interface so we can capture packets on that same interface only
    */
    if(interface) {

        struct ifreq ifr;
        memset(&ifr, 0, sizeof(ifr));
        strncpy(ifr.ifr_name, interface, IFNAMSIZ-1);
        if(setsockopt(raw_socket, SOL_SOCKET, SO_BINDTODEVICE, 
                        (void*)&ifr, sizeof(ifr)) < 0) {
            
            fprintf(stderr, "%s|--[!]%s Error setting the interface options %s | %s\n", blue, reset, interface, strerror(errno));
            return 1;
        }
    }
    //for sotring the packet
    unsigned char *packetBuffer = (unsigned char *) malloc(65534); //Large enough

    memset(packetBuffer, 0, sizeof(packetBuffer));  //zero it out
    if(file_name) {
        sprintf(file_name, "%s.csv", file_name);
        fp = fopen(file_name, "a+");
        if(fp == NULL) {
            fprintf(stderr, "%s|--[!]%s Failed to creating/opening output file %s\n", blue, reset, strerror(errno));
            return 1;
        }
    }
    
    printf("%s|--[*]%s Packet Sniffer Started\n", blue, reset);
    if(interface)
        printf("%s|--[*]%s Capturing on %s...\n", blue, reset, interface);
    else
       printf("%s|--[*]%s Capturing on any(or all) interface...\n", blue, reset, interface);
    
    
    if(proto == IPPROTO_TCP)
        printf("%s|--[*]%s Capturing TCP packets only...\n", blue, reset);
  
    else if(proto == IPPROTO_UDP)
        printf("%s|--[*]%s Capturing UDP packets only...\n", blue, reset);
    else if(proto == IPPROTO_ICMP)
        printf("%s|--[*]%s Capturing ICMP packets only...\n", blue, reset);
    else 
        printf("%s|--[*]%s Capturing ALL packets...\n", blue, reset);
    //Let's enter our infinte loop to keep receiving packets.

    while(1) {

        struct sockaddr serv_addr;
        socklen_t serv_len = sizeof(serv_addr);

        int bytes_received;

        bytes_received = recvfrom(raw_socket, packetBuffer, 65534, 0,
            &serv_addr, &serv_len);

        if(bytes_received < 1) {

            fprintf(stderr, "%s|--[*]%s Call to recvfrom failed %s\n", blue, reset, strerror(errno));
            return 1;
        }
        check_packet_header(packetBuffer, bytes_received);
    }

    close(raw_socket);
    printf("%s|--[*]%s Finsihed\n", blue, reset);

    return 0;

}

// A function for checking/processing packets

void check_packet_header(unsigned char *packet, int packt_size) {

    ++total;
    // we need to cast the packet to ip header, so we can identify which packet protocl was
    struct iphdr *ip_header = (struct iphdr*)(packet + sizeof(struct ethhdr));

    switch(ip_header->protocol) {

        case 1:  //ICMP protocol
            ++icmp;
            icmp_packet_header(packet, packt_size);
            break;
        case 2: //IGMP protocol
            ++igmp;
            break;
        case 6: //TCP protocol
            ++tcp;
            tcp_packet_header(packet, packt_size);
            break;

        case 17: //UDP protocol
            ++udp;
            udp_packet_header(packet, packt_size);
            break;

        default:
            ++others;
            break;
    }

    
}

//For printing the ethernet header
void print_ethernet_header(unsigned char* packt, int packt_size) {

    struct ethhdr *ethheader = (struct ethhdr*)packt;

    if(fp != NULL) {
        fprintf(fp, "\nETHERNET HEADER\n");
        fprintf(fp, "[%.2X-%.2X-%.2X-%.2X-%.2X-%.2X => %.2X-%.2X-%.2X-%.2X-%.2X-%.2X, protcol(%u)]\n", 
        ethheader->h_source[0], ethheader->h_source[1], ethheader->h_source[2], ethheader->h_source[3], ethheader->h_source[4], ethheader->h_source[5],
        ethheader->h_dest[0], ethheader->h_dest[1], ethheader->h_dest[2], ethheader->h_dest[3], ethheader->h_dest[4], ethheader->h_dest[5],
        (unsigned short)ethheader->h_proto, reset);
    }
    printf("%sETHERNET HEADER%s\n", green, reset);
    printf("\t %ssource %s=> %s%.2X-%.2X-%.2X-%.2X-%.2X-%.2X\n", yellow, white, red, ethheader->h_source[0], ethheader->h_source[1], ethheader->h_source[2], ethheader->h_source[3], ethheader->h_source[4], ethheader->h_source[5]);
    printf("\t %sdestination %s=> %s%.2X-%.2X-%.2X-%.2X-%.2X-%.2X\n",yellow, white, red, ethheader->h_dest[0], ethheader->h_dest[1], ethheader->h_dest[2], ethheader->h_dest[3], ethheader->h_dest[4], ethheader->h_dest[5]);
    printf("\t %sprotocol %s=>  %s%u%s\n", yellow, white, red, (unsigned short)ethheader->h_proto, reset);

}

//Print the ip header

void ip_packet_header(unsigned char *packt, int packt_size) {

    print_ethernet_header(packt, packt_size);
    struct iphdr *ipheader = (struct iphdr*)(packt + sizeof(struct ethhdr));
    unsigned int ipheaderlen = ipheader->ihl * 4;

    //For storing source and destination ip address
    struct sockaddr_in saddr, daddr;
    memset(&saddr, 0, sizeof(saddr));
    saddr.sin_addr.s_addr = ipheader->saddr;

    memset(&daddr, 0, sizeof(daddr));
    daddr.sin_addr.s_addr = ipheader->daddr;

    if(fp != NULL) {
        fprintf(fp, "\nIP HEADER \n");
        fprintf(fp, "\t [ihl(%d), ", (unsigned int)ipheaderlen);
        fprintf(fp, "version(%d), ",(unsigned int)ipheader->version);
        fprintf(fp, "protocol(%d), ",(unsigned int)ipheader->protocol);
        fprintf(fp, "tos(%d), ",(unsigned int)ipheader->tos);
        fprintf(fp, "tot_len(%d), ", (unsigned int)ipheader->tot_len);
        fprintf(fp, "id(%d), ", ntohs(ipheader->id));
        fprintf(fp, "check(%d), ", ntohs(ipheader->check));
        fprintf(fp, "frag_off(%d), ", (unsigned int)ipheader->frag_off);
        fprintf(fp, "ttl(%d), ", ntohs(ipheader->ttl));
        fprintf(fp, "source(%s), ", inet_ntoa(saddr.sin_addr));
        fprintf(fp, "destination(%s)]\n", inet_ntoa(daddr.sin_addr));
    }
    printf("%sIP HEADER%s \n", green, reset);
    printf("\t %sihl %s=> %s%d(Length)\n", yellow, white, red, (unsigned int)ipheaderlen);
    printf("\t %sversion %s=> %s%d\n", yellow, white, red, (unsigned int)ipheader->version);
    printf("\t %sprotocol %s=> %s%d\n", yellow, white, red, (unsigned int)ipheader->protocol);
    printf("\t %stos %s=> %s%d(TypeOfService)\n", yellow, white, red, (unsigned int)ipheader->tos);
    printf("\t %stot_len %s=> %s%d(TotalLength)\n", yellow, white, red, (unsigned int)ipheader->tot_len);
    printf("\t %sid %s=> %s%d\n", yellow, white, red, ntohs(ipheader->id));
    printf("\t %scheck %s=> %s%d(Checksum)\n", yellow, white, red, ntohs(ipheader->check));
    printf("\t %sfrag_off %s=> %s%d(Fragment off)\n", yellow, white, red, (unsigned int)ipheader->frag_off);
    printf("\t %sttl %s=> %s%d(TimeToLeave)\n", yellow, white, red, ntohs(ipheader->ttl));
    printf("\t %ssource %s=> %s%s(IP)\n", yellow, white, red, inet_ntoa(saddr.sin_addr));
    printf("\t %sdestination %s=> %s%s(IP)%s\n", yellow, white, red, inet_ntoa(daddr.sin_addr), reset);
    
}

//For printing TCP header packet

void tcp_packet_header(unsigned char *packt, int packt_size) {

    unsigned short ipheader_len;

    struct iphdr *ipheader = (struct iphdr*)(packt + sizeof(struct ethhdr));
    ipheader_len = ipheader->ihl * 4;
    /**
     * Print the IP header of this packet
    */

   ip_packet_header(packt, packt_size);

   /**
    * Create a TCP header structure for printing the TCP header
    *  and cast it to the packet.
   */

    struct tcphdr *tcpheader = (struct tcphdr*)(packt + ipheader_len + sizeof(struct ethhdr));
    unsigned int tcpheader_len = tcpheader->doff*4;

    // Total size fo this header
    int tot_header_size = (tcpheader_len + ipheader_len + sizeof(struct ethhdr));
    if(fp != NULL) {
        fprintf(fp, "\nTCP HEADER\n");
        fprintf(fp, "[source(%u), ", ntohs(tcpheader->source));
        fprintf(fp, "destination(%u), ", ntohs(tcpheader->dest));
        fprintf(fp, "seq(%u), ", ntohl(tcpheader->seq));
        fprintf(fp, "ack_seq(%u), ",ntohl(tcpheader->ack_seq));
        fprintf(fp, "syn(%d), ", (unsigned int)tcpheader->syn);
        fprintf(fp, "ack(%d), ", (unsigned int)tcpheader->ack);
        fprintf(fp, "rst(%d), ", (unsigned int)tcpheader->rst);
        fprintf(fp, "fin(%d), ", (unsigned int)tcpheader->fin);
        fprintf(fp, "psh(%d), ", (unsigned int)tcpheader->psh);
        fprintf(fp, "urg(%d), ", (unsigned int)tcpheader->urg);
        fprintf(fp, "window(%d), ", ntohs(tcpheader->window));
        fprintf(fp, "check(%d), ", ntohs(tcpheader->check));
        fprintf(fp, "urg_ptr(%d)]\n", tcpheader->urg_ptr);
        
    }

    printf("%sTCP HEADER%s\n", green, reset);
    printf("\t %ssource %s=> %s%u(Port)\n", yellow, white, red, ntohs(tcpheader->source));
    printf("\t %sdestination %s=> %s%u(Port)\n", yellow, white, red, ntohs(tcpheader->dest));
    printf("\t %sseq %s=> %s%u(SequenceNumber)\n", yellow, white, red, ntohl(tcpheader->seq));
    printf("\t %sack_seq %s=> %s%u(AcknowlegeNumber)\n", yellow, white, red, ntohl(tcpheader->ack_seq));
    printf("\t %ssyn %s=> %s%d\n", yellow, white, red, (unsigned int)tcpheader->syn);
    printf("\t %sack %s=> %s%d\n", yellow, white, red, (unsigned int)tcpheader->ack);
    printf("\t %srst %s=> %s%d\n", yellow, white, red, (unsigned int)tcpheader->rst);
    printf("\t %sfin %s=> %s%d\n", yellow, white, red, (unsigned int)tcpheader->fin);
    printf("\t %spsh %s=> %s%d\n", yellow, white, red, (unsigned int)tcpheader->psh);
    printf("\t %surg %s=> %s%d\n", yellow, white, red, (unsigned int)tcpheader->urg);
    printf("\t %swindow %s=> %s%d\n", yellow, white, red, ntohs(tcpheader->window));
    printf("\t %scheck %s=> %s%d(Checksum)\n", yellow, white, red, ntohs(tcpheader->check));
    printf("\t %surg_ptr %s=> %s%d(UrgentPointer)%s\n", yellow, white, red, tcpheader->urg_ptr, reset);

    printf("################################\n");
    if(fp != NULL)
        fprintf(fp, "################################\n");
    printf("\t%sDUMP DATA%s\n", blue, reset);
    //print IP header data
    printf("%sIP DATA%s\n", yellow, reset);
    print_packet_data(packt, ipheader_len);

    //print TCP header data
    printf("\n%sTCP DATA%s\n", yellow, reset);
    print_packet_data(packt, tcpheader_len);

    //print Data payload
    printf("\n%sDATA PAYLOAD%s\n", yellow, reset);
    print_packet_data(packt, packt_size - tot_header_size);
    printf("\n################################\n");
    if(fp != NULL)
        fprintf(fp, "################################\n");

}

/**
 * Function for printing UDP headers and data 
*/

void udp_packet_header(unsigned char *packt, int packt_size) {

    unsigned short ipheader_len;
    struct iphdr *ipheader = (struct iphdr*)(packt + sizeof(struct ethhdr));
    ipheader_len = ipheader->ihl * 4;

    // Print the ip header for this packet
    ip_packet_header(packt, packt_size);

    // Create the udp structure

    struct udphdr *udpheader = (struct udphdr*)(packt + ipheader_len + sizeof(struct ethhdr));
    unsigned int udpheader_len = udpheader->len;
    int tot_header_size = udpheader_len + ipheader_len + sizeof(struct ethhdr);
    if(fp != NULL) {
        fprintf(fp, "\nUDP HEADERS: \n");
        fprintf(fp, "\t [source(%d), ", ntohs(udpheader->source));
        fprintf(fp, "destination(%d), ", ntohs(udpheader->dest));
        fprintf(fp, "length(%d), ", ntohs(udpheader_len));
        fprintf(fp, "check(%d)]\n", ntohs(udpheader->check));

    }
  

    printf("%sUDP HEADERS%s\n", green, reset);
    printf("\t %ssource %s=> %s%d(Port)\n", yellow, white, red, ntohs(udpheader->source));
    printf("\t %sdestination %s=> %s%d(Port)\n", yellow, white, red, ntohs(udpheader->dest));
    printf("\t %slength %s=> %s%d\n", yellow, white, red, ntohs(udpheader_len));
    printf("\t %scheck %s=> %s%d%s(Checksum)\n", yellow, white, red, ntohs(udpheader->check), reset);

    printf("################################\n");
    if(fp != NULL)
        fprintf(fp, "################################\n");
    printf("\t%sDUMP DATA%s\n", blue, reset);
    //print IP header data
    printf("%sIP DATA%s\n", yellow, reset);
    print_packet_data(packt, ipheader_len);

    //print TCP header data
    printf("\n%sUDP DATA%s\n", yellow, reset);
    print_packet_data(packt, udpheader_len);

    //print Data payload
    printf("\n%sDATA PAYLOAD%s\n", yellow, reset);
    print_packet_data(packt, packt_size - tot_header_size);
    printf("\n################################\n");
    if(fp != NULL)
        fprintf(fp, "################################\n");
}

// For printing the ICMP headers and data

void icmp_packet_header(unsigned char *packt, int packt_size) {

    unsigned short ipheader_len;
    struct iphdr *ipheader = (struct iphdr*)(packt + sizeof(struct ethhdr));
    ipheader_len = ipheader->ihl * 4;

    // Print the ip header for this packet
    ip_packet_header(packt, packt_size);

    struct icmphdr *icmpheader = (struct icmphdr*)(packt + sizeof(struct ethhdr) + ipheader_len);
    int icmpheader_len = sizeof(icmpheader);
    int tot_header_size = icmpheader_len + ipheader_len + sizeof(struct ethhdr);

    if(fp != NULL) {
        fprintf(fp, "\nICMP HEADERS: \n");
        fprintf(fp, "\t [type(%d), ", (unsigned int)icmpheader->type);
        fprintf(fp, "code(%d), ", (unsigned int)icmpheader->code);
        fprintf(fp, "checksum(%d), ", ntohs(icmpheader->checksum));
        fprintf(fp, "id(%d), ", ntohs(icmpheader->un.echo.id));
        fprintf(fp, "sequence(%d)]\n", ntohs(icmpheader->un.echo.sequence));

    }
    printf("%sICMP HEADERS%s\n", green, reset);
    printf("\t %stype %s=> %s%d", yellow, white, red, (unsigned int)icmpheader->type);
    switch((unsigned int)icmpheader->type) {
        case ICMP_ECHOREPLY:
            printf("(Echo reply)\n");
            break;
        case ICMP_DEST_UNREACH:
            printf("(Destination unreachable)\n");
            break;
        case ICMP_SOURCE_QUENCH:
            printf("(Source quench)\n");
            break;
        case ICMP_REDIRECT:
            printf("(Redirect(change route))\n");
            break;
        case ICMP_ECHO:
            printf("(Echo request)\n");
            break;
        case ICMP_TIME_EXCEEDED:
            printf("(Time exceeded)\n");
            break;
        case ICMP_PARAMETERPROB:
            printf("(Parameter problem)\n");
            break;
        case ICMP_TIMESTAMP:
            printf("(Timestamp request)\n");
            break;
        case ICMP_TIMESTAMPREPLY:
            printf("(Timestamp reply)\n");
            break;
        case ICMP_INFO_REQUEST:
            printf("(Information request)\n");
            break;
        case ICMP_INFO_REPLY:
            printf("(Information reply)\n");
            break;
        case ICMP_ADDRESS:
            printf("(Address mask request)\n");
            break;
        case ICMP_ADDRESSREPLY:
            printf("(Address mask reply)\n");
            break;
        default:
            break;
    }
    printf("\t %scode %s=> %s%d\n", yellow, white, red, (unsigned int)icmpheader->code);
    printf("\t %schecksum %s=> %s%d\n", yellow, white, red, ntohs(icmpheader->checksum));
    printf("\t %sid %s %s%d\n", yellow, white, red, ntohs(icmpheader->un.echo.id));
    printf("\t %ssequence %s %s%d%s\n", yellow, white, red, ntohs(icmpheader->un.echo.sequence), reset);


    printf("################################\n");
    if(fp != NULL)
        fprintf(fp, "\n################################\n");
    printf("\t%sDUMP DATA%s\n", blue, reset);
    //print IP header data
    printf("%sIP DATA%s\n", yellow, reset);
    print_packet_data(packt, ipheader_len);

    //print TCP header data
    printf("\n%sICMP DATA%s\n", yellow, reset);
    print_packet_data(packt, icmpheader_len);

    //print Data payload
    printf("\n%sDATA PAYLOAD%s\n", yellow, reset);
    print_packet_data(packt, packt_size - tot_header_size);
    printf("\n################################\n");
    if(fp != NULL)
        fprintf(fp, "\n################################\n");

}

/**
 * This function is use for printing the actaul packet data
*/

void print_packet_data(unsigned char *packt_data, int data_size) {

    int i = 0, j = 0;

    for(; i < data_size; ++i) {

        //If one line of printing hexa-decimal is complete
        if(i != 0 && i%16 == 0) {

            //print a space
            printf("   ");
            if(fp != NULL) {
                fprintf(fp, "  ");
            }
            for(j = i - 16; j < i; ++j) {

                //If the data is an alpabet or a number, then print it
                if(packt_data[j] >= 32 && packt_data[j] <= 128) {
                    printf("%c", (unsigned char)packt_data[j]);
                    if(fp != NULL)
                        fprintf(fp, "%c", (unsigned char)packt_data[j]);
                } else {//else print a dot
                    printf(".");
                    if(fp != NULL)
                        fprintf(fp, ".");
                }
            }
            // print a new line
            printf("\n");
            if(fp != NULL)
                fprintf(fp, "\n");
        }

        //if one line of printing the hex is complete, then print a space
        if(i%16 == 0) {
            printf(" ");
            if(fp != NULL)
                fprintf(fp, " ");
        }
        printf(" %02X", (unsigned int)packt_data[i]);
        if(fp != NULL)
            fprintf(fp, " %02X", (unsigned int)packt_data[i]);

    }
}