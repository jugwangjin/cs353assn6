#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <stdio.h>
#include <pcap.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

extern char *inet_ntoa();


void stop_pcap_loop(int signo);

pcap_t *p;               /* packet capture descriptor */

int main(int argc, char **argv) {
    struct pcap_stat ps;     /* packet statistics */
    pcap_dumper_t *pd;       /* pointer to the dump file */
    const char filename[] = "./prob1.pcap";       /* name of savefile for dumping packet data */
    char errbuf[PCAP_ERRBUF_SIZE];  /* buffer to hold error text */
    int snaplen = 65535;        /* amount of data per packet  (http://www.tcpdump.org/manpages/pcap.3pcap.html) */
    int promisc = 0;         /* do not change mode; if in promiscuous */                 /* mode, stay in it, otherwise, do not */
    int to_ms = 0;        /* timeout, in milliseconds */
    uint32_t net = 0;         /* network IP address */
    uint32_t mask = 0;        /* network address mask */
    bpf_u_int32 maskp;          /* subnet mask               */
    bpf_u_int32 netp;           /* ip     
    char netstr[INET_ADDRSTRLEN];   /* dotted decimal form of address */
    char maskstr[INET_ADDRSTRLEN];  /* dotted decimal form of net mask */
    int linktype = 0;        /* data link type */
    struct bpf_program fp;      /* hold compiled program     */
    char *dev; 

    const char rule[] = "udp or tcp or icmp";


    dev = pcap_lookupdev(errbuf);
    if(dev == NULL)
    { 
        fprintf(stderr,"%s\n",errbuf); 
        exit(1); 
    }
    printf("pcap_lookupdev() complete\n");

    if (pcap_lookupnet(dev, &netp, &maskp, errbuf) < 0) {
        fprintf(stderr, "Error looking up network: %s\n", errbuf);
        return 3;
    }
    printf("pcap_lookupnet() complete\n");

    if (!(p = pcap_open_live(dev, snaplen, promisc, to_ms, errbuf))) {
        fprintf(stderr, "Error opening interface %s: %s\n", dev, errbuf);
        return 2;
    }
    printf("pcap_open_live() complete\n");

    if(pcap_compile(p,&fp,rule,0,netp) == -1){ 
        fprintf(stderr,"Error calling pcap_compile\n"); 
        exit(1); 
    }
    printf("pcap_compile() complete\n");

    if(pcap_setfilter(p,&fp) == -1){ 
        fprintf(stderr,"Error setting filter\n"); 
        exit(1); 
    }
    printf("pcap_setfilter() complete\n");

    if ((pd = pcap_dump_open(p,filename)) == NULL) {
        fprintf(stderr, "Error opening savefile \"%s\" for writing: %s\n", filename, pcap_geterr(p));
        return 7;
    }
    printf("pcap_dump_open() complete\n");

    printf("pcap_dispatch start\n");
    signal(SIGALRM, stop_pcap_loop);
    alarm(50);
    // pcap_dispatch(p,0,pcap_dump,(u_char *)pd);
    pcap_loop(p,-1,pcap_dump,(u_char *)pd);
    printf("pcap_dispatch end\n");

    pcap_dump_close(pd);  
    pcap_close(p); 
}

void stop_pcap_loop(int signo)
{
    pcap_breakloop(p);
}