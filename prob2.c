
#include <netinet/in.h>
#include <net/ethernet.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>

#define LINE_LEN 16

// IP header structure
struct ip *iph;
struct tcphdr *tcph;
struct udphdr *udph;

int main(int argc, char **argv)
{
	pcap_t *fp;
	char errbuf[PCAP_ERRBUF_SIZE];
	struct pcap_pkthdr *header;
	const u_char *pkt_data;
	u_int i=0;
	int res;
    const char filename[] = "./prob1.pcap";
    
    int sport = 0;
    int dport = 0;

    long startsec = 0;
    long startusec = 0;
    long endsec = 0;
    long endusec = 0;

    int count = 0;
    long totallen = 0;

    int count_tcp = 0;
    int count_udp = 0;
    int count_icmp = 0;
    long totallen_tcp = 0;
    long totallen_udp = 0;
    long totallen_icmp = 0;

    long endhost[20] = {0};
    int endhost_defined[20] = {0};
    int endhost_count[20] = {0};
    long endhost_totallen[20] = {0};

    int count_http = 0;
    int count_ftp = 0;
    int count_dns = 0;
    int count_ssh = 0;
    long totallen_http = 0;
    long totallen_ftp = 0;
    long totallen_dns = 0;
    long totallen_ssh = 0;

	/* Open the capture file */
	if ((fp = pcap_open_offline(filename,			// name of the device
						 errbuf						// error buffer
						 )) == NULL)
	{
		fprintf(stderr,"\nUnable to open the file %s.\n", filename);
		return -1;
	}
	
	/* Retrieve the packets from the file */
	while((res = pcap_next_ex(fp, &header, &pkt_data)) >= 0)
	{
        struct ether_header *ep;
        unsigned short ether_type;   


        // read Ethernet header
        ep = (struct ether_header *)pkt_data;
        pkt_data += sizeof(struct ether_header);

        // protocol type 
        ether_type = ntohs(ep->ether_type);



        // IP type
        if (ether_type == ETHERTYPE_IP)
        {
            // total count
            totallen += header->len;
            iph = (struct ip *)pkt_data;

            // TCP
            if (iph->ip_p == IPPROTO_TCP)
            {
                totallen_tcp += header->len;
                count_tcp++;

                tcph = (struct tcphdr *)(pkt_data + iph->ip_hl * 4);
                // tcph = (struct tcphdr *)(pkt_data + sizeof(struct ip));
                sport = tcph->th_sport;
                dport = tcph->th_dport;
            }
            // UDP
            else if (iph->ip_p == IPPROTO_UDP)
            {
                totallen_udp += header->len;
                count_udp++;

                udph = (struct udphdr *)(pkt_data + iph->ip_hl * 4);
                // udph = (struct udphdr *)(pkt_data + sizeof(struct ip));
                sport = udph->uh_sport;
                dport = udph->uh_dport;
            }
            // ICMP
            else if (iph->ip_p == IPPROTO_ICMP)
            {
                totallen_icmp += header->len;
                count_icmp++;
                sport = -1;
                dport = -1;
            }else{
                sport = -1;
                dport = -1;
            }
            sport = ntohs(sport);
            dport = ntohs(dport);
            // each endpoint
            long dhost;
            long shost;
            dhost = 0;
            shost = 0;
            for(int j=0; j<6; j++){
                dhost = dhost << 8;
                shost = shost << 8;
                dhost += (ep->ether_dhost[j]);
                shost += (ep->ether_shost[j]);
            }
            for(int i=0; i<20; i++){
                if(endhost_defined[i] == 1 && endhost[i] == dhost){
                    endhost_count[i]++;
                    endhost_totallen[i] += header->len;
                    break;
                }else if(endhost_defined[i] == 0){
                    endhost[i] = dhost;
                    endhost_defined[i] = 1;
                    endhost_count[i]++;
                    endhost_totallen[i] += header->len;
                    break;
                }
            }      
            for(int i=0; i<20; i++){
                if(endhost_defined[i] == 1 && endhost[i] == shost){
                    endhost_count[i]++;
                    endhost_totallen[i] += header->len;
                    break;
                }else if(endhost_defined[i] == 0){
                    endhost[i] = shost;
                    endhost_defined[i] = 1;
                    endhost_count[i]++;
                    endhost_totallen[i] += header->len;
                    break;
                }
            }      

            // HTTP 
            if (sport == 80 || sport == 443 || dport == 80 || dport == 443) {
                totallen_http = header->len;
                count_http++;
            }
            //FTP
            if (sport == 20 || sport == 21 || dport == 20 || dport == 21) {
                totallen_ftp = header->len;
                count_ftp++;
            }   
            //DNS
            if (sport == 53 || dport == 53) {
                totallen_dns = header->len;
                count_dns++;
            }   
            //SSH
            if (sport == 22 || dport == 22) {
                totallen_ssh = header->len;
                count_ssh++;
            }        
        }

        // time difference between first and last packet
        if(count==0)
        {
            startsec = header->ts.tv_sec;
            startusec = header->ts.tv_usec;
        }
        endsec = header->ts.tv_sec;
        endusec = header->ts.tv_usec;

        // total count
        count++;
    }
	
	
	if (res == -1)
	{
		printf("Error reading the packets: %s\n", pcap_geterr(fp));
	}
	
    printf("Total packets are %d and total length is %ld\n", count, totallen);
    printf("The time difference between the first and the last packet is %lf-%lf=%lf\n", (endsec*1000000+endusec)/(float)1000000, (startsec*1000000+startusec)/(float)1000000, (endsec*1000000+endusec-(startsec*1000000+startusec))/(float)1000000);
    printf("The number of packet and total bytes of TCP is %d and %ld\n", count_tcp, totallen_tcp);
    printf("The number of packet and total bytes of UDP is %d and %ld\n", count_udp, totallen_udp);
    printf("The number of packet and total bytes of ICMP is %d and %ld\n", count_icmp, totallen_icmp);
    for(int i=0; i<20; i++){
        if(endhost_defined[i] == 1){
            printf("The number of packet and total bytes of end host %lx is %d and %ld\n", endhost[i], endhost_count[i], endhost_totallen[i]);
        }
    }
    printf("The number of packet and total bytes of FTP is %d and %ld\n", count_ftp, totallen_ftp);
    printf("The number of packet and total bytes of SSH is %d and %ld\n", count_ssh, totallen_ssh);
    printf("The number of packet and total bytes of DNS is %d and %ld\n", count_dns, totallen_dns);
    printf("The number of packet and total bytes of HTTP is %d and %ld\n", count_http, totallen_http);
    printf("The average packet size is %lf\n", totallen/(double)count);
    printf("The average packet inter-arrival time is %lf\n", ((endsec*1000000+endusec-(startsec*1000000+startusec))/(float)1000000)/(count-1));
	pcap_close(fp);
	return 0;
}