/*************************************************************************
	> File Name: main.c
	> Author:hua 
	> Mail: 
	> Created Time: 2017年05月22日 星期一 18时04分11秒
 ************************************************************************/

#include<stdio.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <linux/types.h>
#include <netinet/in.h>
#define __FAVOR_BSD 
#include <netinet/udp.h>
#define __FAVOR_BSD 
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <netpacket/packet.h>
#include <net/ethernet.h>
#include <arpa/inet.h>
#include <string.h>
#include <signal.h>
#include <net/if.h>
#include <stdio.h>
#include <sys/uio.h>
#include <fcntl.h>
#include <unistd.h>
#include <linux/filter.h>
#include <stdlib.h>

#define ETH_HDR_LEN 14
#define IP_HDR_LEN 20
#define UDP_HDR_LEN 8
#define TCP_HDR_LEN 20

#define IP4_HDRLEN 20
#define TCP_HDRLEN 20 
#define ETH_HDRLEN 14
#define UDP_HDRLEN 8

static int sock;

void sig_handler(int sig) 
{
    struct ifreq ethreq;
    if(sig == SIGTERM)
        printf("SIGTERM recieved, exiting.../n");
    else if(sig == SIGINT)
        printf("SIGINT recieved, exiting.../n");
    else if(sig == SIGQUIT)
        printf("SIGQUIT recieved, exiting.../n");
    // turn off the PROMISCOUS mode 
    strncpy(ethreq.ifr_name, "eth1", IFNAMSIZ);
    if(ioctl(sock, SIOCGIFFLAGS, &ethreq) != -1) {
        ethreq.ifr_flags &= ~IFF_PROMISC;
        ioctl(sock, SIOCSIFFLAGS, &ethreq);
    }
    close(sock);
    exit(0);
}
uint16_t
checksum (uint16_t *addr, int len)
{
  int count = len;
  register uint32_t sum = 0;
  uint16_t answer = 0;

  // Sum up 2-byte values until none or only one byte left.
  while (count > 1) {
    sum += *(addr++);
    count -= 2;
  }

  // Add left-over byte, if any.
  if (count > 0) {
    sum += *(uint8_t *) addr;
  }

  // Fold 32-bit sum into 16 bits; we lose information by doing this,
  // increasing the chances of a collision.
  // sum = (lower 16 bits) + (upper 16 bits shifted right 16 bits)
  while (sum >> 16) {
    sum = (sum & 0xffff) + (sum >> 16);
  }

  // Checksum is one's compliment of sum.
  answer = ~sum;

  return (answer);
}

// Build IPv4 TCP pseudo-header and call checksum function.
uint16_t
tcp4_checksum (struct ip iphdr, struct tcphdr tcphdr, uint8_t *payload, int payloadlen)
{
  uint16_t svalue;
  char buf[IP_MAXPACKET], cvalue;
  char *ptr;
  int i, chksumlen = 0;

  ptr = &buf[0];  // ptr points to beginning of buffer buf

  // Copy source IP address into buf (32 bits)
  memcpy (ptr, &iphdr.ip_src.s_addr, sizeof (iphdr.ip_src.s_addr));
  ptr += sizeof (iphdr.ip_src.s_addr);
  chksumlen += sizeof (iphdr.ip_src.s_addr);

  // Copy destination IP address into buf (32 bits)
  memcpy (ptr, &iphdr.ip_dst.s_addr, sizeof (iphdr.ip_dst.s_addr));
  ptr += sizeof (iphdr.ip_dst.s_addr);
  chksumlen += sizeof (iphdr.ip_dst.s_addr);

  // Copy zero field to buf (8 bits)
  *ptr = 0; ptr++;
  chksumlen += 1;

  // Copy transport layer protocol to buf (8 bits)
  memcpy (ptr, &iphdr.ip_p, sizeof (iphdr.ip_p));
  ptr += sizeof (iphdr.ip_p);
  chksumlen += sizeof (iphdr.ip_p);

  // Copy TCP length to buf (16 bits)
  svalue = htons (sizeof (tcphdr) + payloadlen);
  memcpy (ptr, &svalue, sizeof (svalue));
  ptr += sizeof (svalue);
  chksumlen += sizeof (svalue);

  // Copy TCP source port to buf (16 bits)
  memcpy (ptr, &tcphdr.th_sport, sizeof (tcphdr.th_sport));
  ptr += sizeof (tcphdr.th_sport);
  chksumlen += sizeof (tcphdr.th_sport);

  // Copy TCP destination port to buf (16 bits)
  memcpy (ptr, &tcphdr.th_dport, sizeof (tcphdr.th_dport));
  ptr += sizeof (tcphdr.th_dport);
  chksumlen += sizeof (tcphdr.th_dport);

  // Copy sequence number to buf (32 bits)
  memcpy (ptr, &tcphdr.th_seq, sizeof (tcphdr.th_seq));
  ptr += sizeof (tcphdr.th_seq);
  chksumlen += sizeof (tcphdr.th_seq);

  // Copy acknowledgement number to buf (32 bits)
  memcpy (ptr, &tcphdr.th_ack, sizeof (tcphdr.th_ack));
  ptr += sizeof (tcphdr.th_ack);
  chksumlen += sizeof (tcphdr.th_ack);

  // Copy data offset to buf (4 bits) and
  // copy reserved bits to buf (4 bits)
  cvalue = (tcphdr.th_off << 4) + tcphdr.th_x2;
  memcpy (ptr, &cvalue, sizeof (cvalue));
  ptr += sizeof (cvalue);
  chksumlen += sizeof (cvalue);

  // Copy TCP flags to buf (8 bits)
  memcpy (ptr, &tcphdr.th_flags, sizeof (tcphdr.th_flags));
  ptr += sizeof (tcphdr.th_flags);
  chksumlen += sizeof (tcphdr.th_flags);

  // Copy TCP window size to buf (16 bits)
  memcpy (ptr, &tcphdr.th_win, sizeof (tcphdr.th_win));
  ptr += sizeof (tcphdr.th_win);
  chksumlen += sizeof (tcphdr.th_win);

  // Copy TCP checksum to buf (16 bits)
  // Zero, since we don't know it yet
  *ptr = 0; ptr++;
  *ptr = 0; ptr++;
  chksumlen += 2;

  // Copy urgent pointer to buf (16 bits)
  memcpy (ptr, &tcphdr.th_urp, sizeof (tcphdr.th_urp));
  ptr += sizeof (tcphdr.th_urp);
  chksumlen += sizeof (tcphdr.th_urp);

  // Copy payload to buf
  memcpy (ptr, payload, payloadlen);
  ptr += payloadlen;
  chksumlen += payloadlen;

  // Pad to the next 16-bit boundary
  for (i=0; i<payloadlen%2; i++, ptr++) {
    *ptr = 0;
    ptr++;
    chksumlen++;
  }

  return checksum ((uint16_t *) buf, chksumlen);
}

uint16_t  
udp4_checksum (struct ip iphdr, struct udphdr udphdr, uint8_t *payload, int payloadlen)  
{  
  char buf[IP_MAXPACKET];  
  char *ptr;  
  int chksumlen = 0;  
  int i;  
  
  ptr = &buf[0];  // ptr points to beginning of buffer buf  
  
  // Copy source IP address into buf (32 bits)  
  memcpy (ptr, &iphdr.ip_src.s_addr, sizeof (iphdr.ip_src.s_addr));  
  ptr += sizeof (iphdr.ip_src.s_addr);  
  chksumlen += sizeof (iphdr.ip_src.s_addr);  
  
  // Copy destination IP address into buf (32 bits)  
  memcpy (ptr, &iphdr.ip_dst.s_addr, sizeof (iphdr.ip_dst.s_addr));  
  ptr += sizeof (iphdr.ip_dst.s_addr);  
  chksumlen += sizeof (iphdr.ip_dst.s_addr);  
  
  // Copy zero field to buf (8 bits)  
  *ptr = 0; ptr++;  
  chksumlen += 1;  
  
  // Copy transport layer protocol to buf (8 bits)  
  memcpy (ptr, &iphdr.ip_p, sizeof (iphdr.ip_p));  
  ptr += sizeof (iphdr.ip_p);  
  chksumlen += sizeof (iphdr.ip_p);  
  
  // Copy UDP length to buf (16 bits)  
  memcpy (ptr, &udphdr.len, sizeof (udphdr.len));  
  ptr += sizeof (udphdr.len);  
  chksumlen += sizeof (udphdr.len);  
  
  // Copy UDP source port to buf (16 bits)  
  memcpy (ptr, &udphdr.source, sizeof (udphdr.source));  
  ptr += sizeof (udphdr.source);  
  chksumlen += sizeof (udphdr.source);  
  
  // Copy UDP destination port to buf (16 bits)  
  memcpy (ptr, &udphdr.dest, sizeof (udphdr.dest));  
  ptr += sizeof (udphdr.dest);  
  chksumlen += sizeof (udphdr.dest);  
  
  // Copy UDP length again to buf (16 bits)  
  memcpy (ptr, &udphdr.len, sizeof (udphdr.len));  
  ptr += sizeof (udphdr.len);  
  chksumlen += sizeof (udphdr.len);  
  
  // Copy UDP checksum to buf (16 bits)  
  // Zero, since we don't know it yet  
  *ptr = 0; ptr++;  
  *ptr = 0; ptr++;  
  chksumlen += 2;  
  
  // Copy payload to buf  
  memcpy (ptr, payload, payloadlen);  
  ptr += payloadlen;  
  chksumlen += payloadlen;  
  
  // Pad to the next 16-bit boundary  
  for (i=0; i<payloadlen%2; i++, ptr++) {  
    *ptr = 0;  
    ptr++;  
    chksumlen++;  
  }  
  
  return checksum ((uint16_t *) buf, chksumlen);  
}  
// Allocate memory for an array of chars.
char *
allocate_strmem (int len)
{
  void *tmp;

  if (len <= 0) {
    fprintf (stderr, "ERROR: Cannot allocate memory because len = %i in allocate_strmem().\n", len);
    exit (EXIT_FAILURE);
  }

  tmp = (char *) malloc (len * sizeof (char));
  if (tmp != NULL) {
    memset (tmp, 0, len * sizeof (char));
    return (tmp);
  } else {
    fprintf (stderr, "ERROR: Cannot allocate memory for array allocate_strmem().\n");
    exit (EXIT_FAILURE);
  }
}

// Allocate memory for an array of unsigned chars.
uint8_t *
allocate_ustrmem (int len)
{
  void *tmp;

  if (len <= 0) {
    fprintf (stderr, "ERROR: Cannot allocate memory because len = %i in allocate_ustrmem().\n", len);
    exit (EXIT_FAILURE);
  }

  tmp = (uint8_t *) malloc (len * sizeof (uint8_t));
  if (tmp != NULL) {
    memset (tmp, 0, len * sizeof (uint8_t));
    return (tmp);
  } else {
    fprintf (stderr, "ERROR: Cannot allocate memory for array allocate_ustrmem().\n");
    exit (EXIT_FAILURE);
  }
}

// Allocate memory for an array of ints.
int *
allocate_intmem (int len)
{
  void *tmp;

  if (len <= 0) {
    fprintf (stderr, "ERROR: Cannot allocate memory because len = %i in allocate_intmem().\n", len);
    exit (EXIT_FAILURE);
  }

  tmp = (int *) malloc (len * sizeof (int));
  if (tmp != NULL) {
    memset (tmp, 0, len * sizeof (int));
    return (tmp);
  } else {
    fprintf (stderr, "ERROR: Cannot allocate memory for array allocate_intmem().\n");
    exit (EXIT_FAILURE);
  }
}


int
create_tcp_frame (uint8_t *snd_ether_frame, char *src_ip, char *dst_ip, uint8_t *src_mac, uint8_t *dst_mac,
                  int ttl, uint8_t *data, int datalen,int spot,unsigned long ack_v, unsigned long seq_v)
{
  int i, status, *ip_flags, *tcp_flags;
  struct ip iphdr;
  struct tcphdr tcphdr;

  // Allocate memory for various arrays.
  ip_flags = allocate_intmem (4);
  tcp_flags = allocate_intmem (8);

  // IPv4 header

  // IPv4 header length (4 bits): Number of 32-bit words in header = 5
  iphdr.ip_hl = IP4_HDRLEN / sizeof (uint32_t);

  // Internet Protocol version (4 bits): IPv4
  iphdr.ip_v = 4;

  // Type of service (8 bits)
  iphdr.ip_tos = 0;

  // Total length of datagram (16 bits): IP header + TCP header + data
  iphdr.ip_len = htons (IP4_HDRLEN + TCP_HDRLEN + datalen);

  // ID sequence number (16 bits): unused, since single datagram
  iphdr.ip_id = htons (0);

  // Flags, and Fragmentation offset (3, 13 bits): 0 since single datagram

  // Zero (1 bit)
  ip_flags[0] = 0;

  // Do not fragment flag (1 bit)
  ip_flags[1] = 1;

  // More fragments following flag (1 bit)
  ip_flags[2] = 0;

  // Fragmentation offset (13 bits)
  ip_flags[3] = 0;

  iphdr.ip_off = htons ((ip_flags[0] << 15)
                      + (ip_flags[1] << 14)
                      + (ip_flags[2] << 13)
                      +  ip_flags[3]);

  // Time-to-Live (8 bits): default to maximum value
  iphdr.ip_ttl = 60;

  // Transport layer protocol (8 bits): 6 for TCP
  iphdr.ip_p = IPPROTO_TCP;

#if 10
  // Source IPv4 address (32 bits)
  if ((status = inet_pton (AF_INET, src_ip, &(iphdr.ip_src))) != 1) {
    fprintf (stderr, "inet_pton() failed.\nError message: %s", strerror (status));
    exit (EXIT_FAILURE);
  }

  // Destination IPv4 address (32 bits)
  if ((status = inet_pton (AF_INET, dst_ip, &(iphdr.ip_dst))) != 1) {
    fprintf (stderr, "inet_pton() failed.\nError message: %s", strerror (status));
    exit (EXIT_FAILURE);
  }

#endif
  // IPv4 header checksum (16 bits): set to 0 when calculating checksum
  iphdr.ip_sum = 0;
  iphdr.ip_sum = checksum ((uint16_t *) &iphdr, IP4_HDRLEN);

  // TCP header

  // Source port number (16 bits)
  tcphdr.th_sport = htons (80);

  // Destination port number (16 bits)
  tcphdr.th_dport = htons (spot);

  // Sequence number (32 bits)
  tcphdr.th_seq = htonl (seq_v);

  // Acknowledgement number (32 bits): 0 in first packet of SYN/ACK process
  tcphdr.th_ack = htonl (ack_v);
 // tcphdr.th_ack = *old_ack;

  // Reserved (4 bits): should be 0
  tcphdr.th_x2 = 0;

  // Data offset (4 bits): size of TCP header in 32-bit words
  tcphdr.th_off = TCP_HDRLEN / 4;

  // Flags (8 bits)

  // FIN flag (1 bit)
  tcp_flags[0] = 1;

  // SYN flag (1 bit): set to 1
  tcp_flags[1] = 0;

  // RST flag (1 bit)
  tcp_flags[2] = 0;

  // PSH flag (1 bit)
  tcp_flags[3] = 1;

  // ACK flag (1 bit)
  tcp_flags[4] = 1;

  // URG flag (1 bit)
  tcp_flags[5] = 0;

  // ECE flag (1 bit)
  tcp_flags[6] = 0;

  // CWR flag (1 bit)
  tcp_flags[7] = 0;

  tcphdr.th_flags = 0;
  for (i=0; i<8; i++) {
    tcphdr.th_flags += (tcp_flags[i] << i);
  }

  // Window size (16 bits)
  tcphdr.th_win = htons (65535);

  // Urgent pointer (16 bits): 0 (only valid if URG flag is set)
  tcphdr.th_urp = htons (0);

  // TCP checksum (16 bits)
  tcphdr.th_sum = tcp4_checksum (iphdr, tcphdr, data, datalen);

  // Fill out ethernet frame header.

  // Destination and Source MAC addresses
  memcpy (snd_ether_frame, dst_mac, 6 * sizeof (uint8_t));
  memcpy (snd_ether_frame + 6, src_mac, 6 * sizeof (uint8_t));

  // Next is ethernet type code (ETH_P_IP for IPv4).
  // http://www.iana.org/assignments/ethernet-numbers
  snd_ether_frame[12] = ETH_P_IP / 256;
  snd_ether_frame[13] = ETH_P_IP % 256;

  // Next is ethernet frame data (IPv4 header + TCP header).

  // IPv4 header
  memcpy (snd_ether_frame + ETH_HDRLEN, &iphdr, IP4_HDRLEN * sizeof (uint8_t));

  // TCP header
  memcpy (snd_ether_frame + ETH_HDRLEN + IP4_HDRLEN, &tcphdr, TCP_HDRLEN * sizeof (uint8_t));

  // TCP data
  memcpy (snd_ether_frame + ETH_HDRLEN + IP4_HDRLEN + TCP_HDRLEN, data, datalen * sizeof (uint8_t));

  // Free allocated memory.
  free (ip_flags);
  free (tcp_flags);

  return (EXIT_SUCCESS);
}

void myprintf(char *buf,int len)
{
    int i;
    for(i=0;i<len;i++)
    {
        printf("%02hhx ",buf[i]);
        if((0==(i%16)&&(i>0))){
            printf("\n");
        }
    }
    printf("\n----------------\n");
}


int
create_udp_frame (uint8_t *snd_ether_frame, char *src_ip, char *dst_ip, uint8_t *src_mac, uint8_t *dst_mac,
                  int ttl, uint8_t *data, int datalen,int dns_spot)
{
  int status, *ip_flags;
  struct ip iphdr;
  struct udphdr udphdr;

  // Allocate memory for various arrays.
  ip_flags = allocate_intmem (4);

  // IPv4 header

  // IPv4 header length (4 bits): Number of 32-bit words in header = 5
  iphdr.ip_hl = IP4_HDRLEN / sizeof (uint32_t);

  // Internet Protocol version (4 bits): IPv4
  iphdr.ip_v = 4;

  // Type of service (8 bits)
  iphdr.ip_tos = 0;

  // Total length of datagram (16 bits): IP header + UDP header + datalen
  iphdr.ip_len = htons (IP4_HDRLEN + UDP_HDRLEN + datalen);

  // ID sequence number (16 bits): unused, since single datagram
  iphdr.ip_id = htons (0);

  // Flags, and Fragmentation offset (3, 13 bits): 0 since single datagram

  // Zero (1 bit)
  ip_flags[0] = 0;
  // do not fragments flag (1 bit)
  ip_flags[1] = 0;

  // More fragments following flag (1 bit)
  ip_flags[2] = 0;

  // Fragmentation offset (13 bits)
  ip_flags[3] = 0;

  iphdr.ip_off = htons ((ip_flags[0] << 15)
                      + (ip_flags[1] << 14)
                      + (ip_flags[2] << 13)
                      +  ip_flags[3]);

  // Time-to-Live (8 bits): default to maximum value
  //iphdr.ip_ttl = ttl;
  iphdr.ip_ttl = 120;

  // Transport layer protocol (8 bits): 17 for UDP
  iphdr.ip_p = IPPROTO_UDP;

  // Source IPv4 address (32 bits)
  if ((status = inet_pton (AF_INET, src_ip, &(iphdr.ip_src))) != 1) {
    fprintf (stderr, "inet_pton() failed.\nError message: %s", strerror (status));
    exit (EXIT_FAILURE);
  }

  // Destination IPv4 address (32 bits)
  if ((status = inet_pton (AF_INET, dst_ip, &(iphdr.ip_dst))) != 1) {
    fprintf (stderr, "inet_pton() failed.\nError message: %s", strerror (status));
    exit (EXIT_FAILURE);
  }
 //ipv4 head checksum 
  iphdr.ip_sum = 0;
  iphdr.ip_sum = checksum ((uint16_t *) &iphdr, IP4_HDRLEN);

  // UDP header

  // Source port number (16 bits): pick a number
  udphdr.uh_sport = htons (53);

  // Destination port number (16 bits): pick a number
  udphdr.uh_dport = htons (dns_spot);

  // Length of UDP datagram (16 bits): UDP header + UDP data
  udphdr.uh_ulen = htons (UDP_HDRLEN + datalen);

  // UDP checksum (16 bits)
  udphdr.uh_sum = udp4_checksum (iphdr, udphdr, data, datalen);

  // Fill out ethernet frame header.

  // Destination and Source MAC addresses
  memcpy (snd_ether_frame, dst_mac, 6 * sizeof (uint8_t));
  memcpy (snd_ether_frame + 6, src_mac, 6 * sizeof (uint8_t));

  // Next is ethernet type code (ETH_P_IP for IPv4).
  // http://www.iana.org/assignments/ethernet-numbers
  snd_ether_frame[12] = ETH_P_IP / 256;
  snd_ether_frame[13] = ETH_P_IP % 256;

  // Next is ethernet frame data (IPv4 header + UDP header + UDP data).
  // IPv4 header
  memcpy (snd_ether_frame + ETH_HDRLEN, &iphdr, IP4_HDRLEN * sizeof (uint8_t));

  // UDP header
  memcpy (snd_ether_frame + ETH_HDRLEN + IP4_HDRLEN, &udphdr, UDP_HDRLEN * sizeof (uint8_t));

  // UDP data
  memcpy (snd_ether_frame + ETH_HDRLEN + IP4_HDRLEN + UDP_HDRLEN, data, datalen * sizeof (uint8_t));

  // Free allocated memory.
  free (ip_flags);

  return (EXIT_SUCCESS);
}

int
main(int argc, char ** argv) {
    int n,ss,dstport;
    int i=0;	
    int date_len;
    int nextack=0;
    int spot=0;
    int dns_spot=0; 
    int node=1; 
    int maxfd=0;
    int query_len=0;
    char destport[2]={0};
    char t_head[20]={0};
    char myget[3]={0x47,0x45,0x54};
    char myudp[4]={0x48,0x54,0x54,0x50};
    char udphead[10]={0x81,0x80,0x00,0x01,0x00,0x01,0x00,0x00,0x00,0x00};
   // char answer[16]={0xc0,0x0c,0x00,0x01,0x00,0x01,0x00,0x00,0x00,0x21,0x00,0x04,0x73,0xe7,0x25,0x22};
  //  char answer[16]={0xc0,0x0c,0x00,0x01,0x00,0x01,0x00,0x00,0x00,0x21,0x00,0x04,0x17,0x3a,0xe2,0x6c};
    char answer[16]={0xc0,0x0c,0x00,0x01,0x00,0x01,0x00,0x00,0x00,0x21,0x00,0x04,0xc0,0xa8,0x02,0x0b};
    unsigned long ack_v;
    unsigned long seq_v;
    long long sum;
    fd_set readfds,testfds;
    uint8_t *snd_ether_frame;
    uint8_t *src_mac, *dst_mac,*data;
    char *interface, *target, *src_ip, *dst_ip, *rec_ip, *tcp_dat, *dns_dat, *udp_dat;
    char *old_ack,*old_seq;
    int  datalen,frame_length,bytes,sendsd;
    struct sockaddr_ll device;
    struct tcphdr s_tcphdr;
    old_ack = allocate_ustrmem (4);
    old_seq = allocate_ustrmem (4);
    src_mac = allocate_ustrmem (6);
    dst_mac = allocate_ustrmem (6);
//	ether_frame = allocate_ustrmem (IP_MAXPACKET);
    data = allocate_ustrmem (IP_MAXPACKET);
	interface = allocate_strmem (40);
	src_ip = allocate_strmem (INET_ADDRSTRLEN);
	dst_ip = allocate_strmem (INET_ADDRSTRLEN);
	tcp_dat = allocate_strmem (IP_MAXPACKET);
	dns_dat = allocate_strmem (IP_MAXPACKET);
//	ip_flags = allocate_intmem (4);
//	tcp_flags = allocate_intmem (8);
//	payload = allocate_strmem (IP_MAXPACKET);
    snd_ether_frame = allocate_ustrmem (IP_MAXPACKET);
    char buf[2048];
    char mybuf[1024];
    char str[1024]="HTTP/1.1 200 OK";
     strcat(str,"\n");
     strcat(str,"Pragma: no-cache\n");
     strcat(str,"Content-Type: text/html\n");
     strcat(str,"Cache-Control: no-cache,no-store\n\n");
     strcat(str,"<html><body>xxx</body></html>");
    unsigned char *ethhead;
    unsigned char *iphead;
    struct ifreq ethreq;
    struct ifreq  myreq;
    struct sigaction sighandle;
    struct sockaddr_in myaddr;
    struct sockaddr_ll addr;

    memcpy(tcp_dat,str,512);    
// ------- get http head -----
    struct iphdr	*iph	= NULL; 
    struct tcphdr	*tcph	= NULL;
    char * payload = NULL;
    struct tcphdr _tcph, *th;
    char * strtemp=NULL;
    char * mysecdata=NULL;
    char * secrity=NULL;
    char * sec=NULL;
    char * temp=NULL;
    unsigned char* packet;
    int plen;

#if 0
        测试访问www.qq.com 
        ping www.qq.com 得到ip地址为:101.226.103.106
        tcpdump -dd host 101.226.103.106
         { 0x28, 0, 0, 0x0000000c },
         { 0x15, 0, 4, 0x00000800 },
         { 0x20, 0, 0, 0x0000001a },
         { 0x15, 8, 0, 0x65e2676a },
         { 0x20, 0, 0, 0x0000001e },
         { 0x15, 6, 7, 0x65e2676a },
         { 0x15, 1, 0, 0x00000806 },
         { 0x15, 0, 5, 0x00008035 },
         { 0x20, 0, 0, 0x0000001c },
         { 0x15, 2, 0, 0x65e2676a },
         { 0x20, 0, 0, 0x00000026 },
         { 0x15, 0, 1, 0x65e2676a },
         { 0x6, 0, 0, 0x0000ffff },
         { 0x6, 0, 0, 0x00000000 },
#endif
        struct sock_filter bpf_code[] = {
            { 0x28, 0, 0, 0x0000000c },
            { 0x15, 0, 5, 0x00000800 },
            { 0x20, 0, 0, 0x0000001a },
            { 0x15, 2, 0, 0x73ec8bae },
            { 0x20, 0, 0, 0x00000026 },
            { 0x15, 0, 1, 0x73ec8ba },
            { 0x6, 0, 0, 0x0000ffff },
            { 0x6, 0, 0, 0x00000000 }
        };

    struct sock_fprog filter;
    filter.len = sizeof(bpf_code)/sizeof(bpf_code[0]);
    filter.filter = bpf_code;

    sighandle.sa_flags = 0;
    sighandle.sa_handler = sig_handler;
    sigemptyset(&sighandle.sa_mask);
    //sigaddset(&sighandle.sa_mask, SIGTERM);
    //sigaddset(&sighandle.sa_mask, SIGINT);
    //sigaddset(&sighandle.sa_mask, SIGQUIT);
    sigaction(SIGTERM, &sighandle, NULL);
    sigaction(SIGINT, &sighandle, NULL);
    sigaction(SIGQUIT, &sighandle, NULL);

    // AF_PACKET allows application to read pecket from and write packet to network device
    // SOCK_DGRAM the packet exclude ethernet header
    // SOCK_RAW raw data from the device including ethernet header
    // ETH_P_IP all IP packets 
    if((sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_IP))) == -1) {
        perror("socket");
        exit(1);
        
    }

    // set NIC to promiscous mode, so we can recieve all packets of the network
    strncpy(ethreq.ifr_name, "eth0", IFNAMSIZ);
    if(ioctl(sock, SIOCGIFFLAGS, &ethreq) == -1) {
        perror("ioctl");
        close(sock);
        exit(1);
    }

#if 0
    ethreq.ifr_flags |= IFF_PROMISC;
    if(ioctl(sock, SIOCSIFFLAGS, &ethreq) == -1) {
        perror("ioctl");
        close(sock);
        exit(1);
    }

    // attach the bpf filter
    if(setsockopt(sock, SOL_SOCKET, SO_ATTACH_FILTER, &filter, sizeof(filter)) == -1) {
        perror("setsockopt");
        close(sock);
        exit(1);
    }
#endif

        
    if ((sendsd = socket (AF_PACKET, SOCK_RAW, htons (ETH_P_ALL))) < 0) {
        perror ("socket() failed to obtain a send socket descriptor ");
        exit (EXIT_FAILURE);
    }
	strcpy(myreq.ifr_name,"eth0");
	ioctl(sendsd,SIOCGIFINDEX,&myreq);
	device.sll_family = AF_PACKET;
        device.sll_ifindex= myreq.ifr_ifindex;
        device.sll_protocol=htons(ETH_P_ALL);
     //   memcpy (device.sll_addr, src_mac, 6 * sizeof (uint8_t));
        device.sll_halen = 6;
     
  while(1) {

#if 0
	FD_ZERO(&readfds);
	FD_SET(sock,&readfds);
	maxfd=sock+1;	
	
	switch(select(maxfd,&readfds,NULL,NULL,NULL))
	{
	  case -1:
		return -1;
		break;
	  case 0:
		break;
	  default:
		if(FD_ISSET(sock,&readfds))
		{	

#endif

#if 10			

			n = recvfrom(sock, buf, sizeof(buf), 0,NULL,NULL);
			if(n < (ETH_HDR_LEN+IP_HDR_LEN+UDP_HDR_LEN)) {
				printf("invalid packet\n");
				continue;
			}

#endif
			ethhead=buf;
			iphead=ethhead+ETH_HDR_LEN;
			if((iphead[9]==IPPROTO_UDP)&&((ethhead[36]<<8|ethhead[37])==53))
			{
				// printf("$$$$$$$$$$$:%s\n",buf);    
				ethhead = buf;
				//--1 memcpy(src_mac,ethhead,6);
				memcpy(src_mac,ethhead,6);
				//src----dst_mac
				memcpy(dst_mac,ethhead+6,6);
				//src--dst 
				date_len=ethhead[16]<<8|ethhead[17];
			//	printf("date -len :%d\n",date_len);
				//--1sprintf(dst_ip,"%d.%d.%d.%d",ethhead[26],ethhead[27],ethhead[28],ethhead[29]);
				sprintf(dst_ip,"%d.%d.%d.%d",ethhead[26],ethhead[27],ethhead[28],ethhead[29]);
				
				sprintf(src_ip,"%d.%d.%d.%d",ethhead[30],ethhead[31],ethhead[32],ethhead[33]);
				//PORT
				printf("src  ip is :%s\n",src_ip);
				dns_spot=ethhead[34]<<8|ethhead[35];
				//  
				query_len=(ethhead[38]<<8|ethhead[39])-20;
				memcpy(dns_dat,ethhead+42,2);
				memcpy(dns_dat+2,udphead,10);
				memcpy(dns_dat+12,ethhead+54,query_len);
				memcpy(dns_dat+12+query_len,answer,16);
				
				
				datalen =query_len+28;
				memcpy (data, dns_dat, datalen * sizeof (uint8_t));
				create_udp_frame(snd_ether_frame, src_ip, dst_ip, src_mac, dst_mac, node, data, datalen,dns_spot);
				frame_length = 6 + 6 + 2 + IP4_HDRLEN + UDP_HDR_LEN + datalen;

				myprintf(snd_ether_frame,frame_length);     
				// printf("frame_length is ***:%d\n",frame_length);
				// Send ethernet frame to socket.
				if ((bytes = sendto (sendsd, snd_ether_frame, frame_length, 0, (struct sockaddr *)&device, 20)) <= 0) {
					perror ("sendto() failed");
					exit (EXIT_FAILURE);
				}else
				{
					printf("****************************sent  mypack is ok ***************************************\n");
				}
					 //sleep(15);
			
			}else{
		
			printf("other udp \n");

			}
			
#if 0
			iph  =(struct iphdr *)( buf+14);	
			tcph = (struct tcphdr *)((char *)iph + iph->ihl*4);
			if(ntohs(tcph->dest) == 80)
		    	{
			 sleep(110);
			  payload = (char*)iph+(iph->ihl*4)+tcph->doff*4; 
			  strtemp = strstr(payload,"GET");
			  if(NULL==strtemp)
			  {
				  return -1;
			  }else
			  {
				  printf("this is ok \n");

			  }
			}
#endif 
			
#if 0
		//	myprintf(buf,strlen(buf));
		//	printf("%d bytes recieved\n", strlen(buf));
			if(0==memcmp(buf+54,myget,3))
			{

				//sleep(15);

				// printf("$$$$$$$$$$$:%s\n",buf);    
				ethhead = buf;
				//dst---src 	
				//--1 memcpy(src_mac,ethhead,6);
				memcpy(src_mac,ethhead,6);
			//	myprintf(src_mac,6);
				//src----dst_mac
				//--1 memcpy(dst_mac,ethhead+5,6);
				memcpy(dst_mac,ethhead+6,6);
			//	myprintf(dst_mac,6);
				//src--dst 
				// memcpy(dst_ip,ethhead+25,4);
				date_len=ethhead[16]<<8|ethhead[17];
			//	printf("date -len :%d\n",date_len);
				//--1sprintf(dst_ip,"%d.%d.%d.%d",ethhead[26],ethhead[27],ethhead[28],ethhead[29]);
				sprintf(dst_ip,"%d.%d.%d.%d",ethhead[26],ethhead[27],ethhead[28],ethhead[29]);
				
			//	src_ip="192.168.1.4";
				//dst--src 
				// memcpy(src_ip,ethhead+29,4);
				//--1sprintf(src_ip,"%d.%d.%d.%d",ethhead[30],ethhead[31],ethhead[32],ethhead[33]);
				sprintf(src_ip,"%d.%d.%d.%d",ethhead[30],ethhead[31],ethhead[32],ethhead[33]);
				//PORT
				//sprintf(spot,"%d",(ethhead[34]<<8|ethhead[35]));
				
				printf("src  ip is :%s\n",src_ip);
				// seq and ack 
				memcpy(old_seq,ethhead+38,4);
			        for(i=0;i<4;i++)
				{
				 ack_v|=((unsigned long)old_seq[3-i]&0xFFu)<<(i*8);
				 
				}	
				 ack_v=ack_v+date_len-40;
				memcpy(old_ack,ethhead+42,4);
				 for(i=0;i<4;i++)
				{
				 seq_v|=((unsigned long)old_ack[3-i]&0xFFu)<<(i*8);
				
				}	
				myprintf(old_ack,sizeof(old_ack));
				printf("dst ip is :%s\n",dst_ip);
				myprintf(old_seq,sizeof(old_ack));
				//if(memcmp(dst_ip,"115.236.139.174",sizeof(dst_ip)))
				
				

				spot=ethhead[34]<<8|ethhead[35];
				// myprintf(ethhead[34]<<8|ethhead[35]);
				printf("the port is :%d\n",spot);
				//   memcpy(t_head,ethhead+33,20);
				//s_tcphdr=(struct tcphdr )(t_head);
				//make a tcp packet for replay http 


				datalen = strlen (tcp_dat);
				printf("the http ok is :%s\n len :%d\n",tcp_dat,datalen);
				memcpy (data, tcp_dat, datalen * sizeof (uint8_t));
				create_tcp_frame (snd_ether_frame, src_ip, dst_ip, src_mac, dst_mac, node, data, datalen,spot,ack_v,seq_v);
				frame_length = 6 + 6 + 2 + IP4_HDRLEN + TCP_HDRLEN + datalen;

				myprintf(snd_ether_frame,frame_length);     
				// printf("frame_length is ***:%d\n",frame_length);
				// Send ethernet frame to socket.
				if ((bytes = sendto (sendsd, snd_ether_frame, frame_length, 0, (struct sockaddr *)&device, 20)) <= 0) {
					perror ("sendto() failed");
					exit (EXIT_FAILURE);
				}else
				{
					printf("****************************sent  mypack is ok ***************************************\n");
				}
			   //    free(snd_ether_frame); 
		//	 sleep(15);
			}
#endif
    }
    close(sock);
    exit(0);
}

