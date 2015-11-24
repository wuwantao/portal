/*
 ============================================================================
 Name        : portal.c
 Author      : yiqun
 Version     :
 Copyright   : Your copyright notice
 Description : Hello World in C, Ansi-style
 ============================================================================
 */

/*
 ============================================================================
 Name        : portal.c
 Author      :
 Version     :
 Copyright   : Your copyright notice
 Description : Hello World in C, Ansi-style
 ============================================================================
 */
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#include <pcap.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <arpa/inet.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <libnet.h>
#include <sqlite3.h>
#include <netdb.h>
struct sendarp_conf {
	char interface[20];
	char dbpath[50];
	char portal_dev[50];
	char portal_server[50];
	char portal_server_ip[16];
	char portal_server_ip_num; // youhua
} conf;
#define CONFIGURE "/etc/sendarp.conf"
#define DEBUG(format,...) printf("File: "__FILE__", Line: %05d: "format"/n",__LINE__,##__VA_ARGS__);
struct ip_list {
	unsigned int ip;
	struct ip_list *next;
};
typedef struct ip_list NODE;
NODE *head = NULL;

char smac[50];
int search(unsigned int ip) {
	NODE *pthis = NULL;
	if (head == NULL) {
		//printf("no data\n");
		return 0;
	}
	pthis = head;
	while (pthis != NULL) {
		if (pthis->ip == ip) {
			return 1;
		} else {
			pthis = pthis->next;
		}
	}
	return 0;

}
void append(unsigned int ip) {
	NODE *tmp;
	NODE *pthis;
	tmp = (NODE *) malloc(sizeof(NODE));
	if (tmp == NULL) {
		printf("malloc failed!\n");
		exit(0);
	}
	tmp->next = NULL;
	tmp->ip = ip;
	if (head == NULL) {
		printf("head == null\n");
		head = tmp;
	} else {
		pthis = head;
		while (pthis->next != NULL) {
			pthis = pthis->next;
		}
		pthis->next = tmp;
	}
}
void pfree(NODE *head) {

	NODE *p, *q;
	p = head;
	while (p->next != NULL) {
		q = p->next;
		p->next = q->next;
		free(q);
	}
	free(p);
}
void display(NODE *head) {
	NODE *p;
	for (p = head; p != NULL; p = p->next) {
		struct in_addr tmp;
		tmp.s_addr = p->ip;
		printf("%s\n", inet_ntoa(tmp));
	}
	printf("\n");

}

void getData() {
	char sql[100] = { 0 };
	int nRow = 0;
	int nColumn = 0;
	sqlite3 *db;
	char *zErrMsg;
	char **azResult;
	int rt = 0;
	int i = 0;
	int j = 0;

	unsigned int ip = 0;

    printf("[getData]conf.dbpath:%s\n",conf.dbpath);
	rt = sqlite3_open(conf.dbpath, &db);

	if (rt != SQLITE_OK) {
        printf("%s\n",sqlite3_errmsg(db));
		DEBUG("%s\n", sqlite3_errmsg(db));
		exit(0);
	}
	sprintf(sql, "select sip from portal");
	rt = sqlite3_get_table(db, sql, &azResult, &nRow, &nColumn, &zErrMsg);
    printf("rt:%d\n");
    printf("nRow:%d\n");
	for (j = 1; j <= nRow; j++) {
		for (i = 0; i < nColumn; i++) {
			if (azResult[i + j * nColumn] != NULL) {
				printf("white:%s\n", azResult[i + j * nColumn]);
				ip = (unsigned int) inet_addr(azResult[i + j * nColumn]);
				append(ip);
			}
		}
	}

	if (db != NULL) {
		sqlite3_close(db);
	}

}

static void init_thread_libnet();
//static u_int8_t httphead[512];
//static u_int8_t httphead_t[] =
u_int8_t httphead[512] = "";
//		"HTTP/1.0 302 Found\n"
//				"Location: http://192.168.3.114:5246/auth/?authip=192.168.2.3&gateway=192.168.3.10\n"
//				"Connection:close\n\n"
//				"<html>\n\t<head>\n\t\t<meta http-equiv=\"Refresh\"content=\"0 ; "
//				"url=http://192.168.3.114:5246/auth/?authip=192.168.2.3&gateway=192.168.3.10\">\n\t</head>\n</html>\n";

static in_addr_t redirector_ip;
static in_addr_t portal_dev;
libnet_t * libnet = NULL;
static u_int8_t blank[128];

static inline void init_thread_libnet() {
	if (!libnet) {
		static char buf[LIBNET_ERRBUF_SIZE];
		libnet = libnet_init(LIBNET_RAW4, NULL, buf);
	}
}

static int http_redirector(const char *packet_content) {
	/*******************************************************************
	 * here we use TCP
	 * when we recv a SYN=1,ACK=0 packet, we just send a syn=1,ack=1 packet
	 * that contains nothing
	 * then we push a packet taht contains
	 *         HTTP/1.0 302 Found
	 *         Location: http://192.168.0.1/
	 *         connection:close
	 *
	 *         please visit http://192.168.0.1
	 *         and then we reset the connection
	 * ****************************************************************/
	struct tcphdr * tcp_head;
	struct udphdr * udp_head;
	struct ether_header *eptr; //以太网帧
	struct iphdr *ip_head;
	if (packet_content == NULL) {
		return 1;
	}
	eptr = (struct ether_header *) packet_content;
	ip_head = (struct iphdr *) (packet_content + sizeof(struct ether_header)); //获得ip数据报的内存地址

	//非 enable 的客户端，现在要开始这般处理了,重定向到 ... 嘿嘿
	redirector_ip = inet_addr(conf.portal_server_ip);
	portal_dev = inet_addr(conf.portal_dev);
	if (ip_head->daddr == redirector_ip || ip_head->daddr == portal_dev) {
		return 1;
	}

	if (ip_head->saddr == redirector_ip || ip_head->saddr == portal_dev) {
		return 1;
	}
	struct in_addr tmp;
	tmp.s_addr = ip_head->daddr;
	if (search(ip_head->daddr) == 1) {
		printf("dip:%sok\n", inet_ntoa(tmp));
		return 1;
	}
	tmp.s_addr = ip_head->saddr;
	if (search(ip_head->saddr) == 1) {
//		printf("sip:%sok\n", inet_ntoa(tmp));
		return 1;
	}

	memset(httphead, 0, sizeof(httphead));
	sprintf(httphead,
			"HTTP/1.0 302 Found\n"
					"Location: http://%s:5246/test/auth.jsp?sip=%s&portal_dev=%s&smac=%s\n"
					"Connection:close\n\n"
					"<html>\n\t<head>\n\t\t<meta http-equiv=\"Refresh\"content=\"0 ; "
					"url=http://%s:5246/test/auth.jsp?sip=%s&portal_dev=%s&smac=%s\">\n\t</head>\n</html>\n",
			conf.portal_server_ip, inet_ntoa(tmp), conf.portal_dev, smac,
			conf.portal_server_ip, inet_ntoa(tmp), conf.portal_dev, smac);
//	conf.authserver, inet_ntoa(tmp), conf.gateway, smac,
//				conf.authserver, inet_ntoa(tmp), conf.gateway, smac);
	printf("httphead:%s\n", httphead);
	//Retrive the tcp header and udp header
	tcp_head = (struct tcphdr*) ((char*) ip_head + ip_head->ihl * 4);
	udp_head = (struct udphdr*) ((char*) ip_head + ip_head->ihl * 4);

	//初始化libnet，每个线程一个 libnet ;)
	init_thread_libnet();

	// http 重定向
	if (ip_head->protocol == IPPROTO_TCP && ntohs(tcp_head->dest) == 80) {
		u_int8_t tcp_flags = ((struct libnet_tcp_hdr *) tcp_head)->th_flags;
		if (tcp_flags == TH_SYN) {
			/********************************
			 * 对于这样的一个握手数据包
			 * 我们应该要建立连接了
			 * 回复一个syn ack 就是了
			 *********************************/
			// here we just echo ack and syn.
			libnet_build_tcp(ntohs(tcp_head->dest), ntohs(tcp_head->source),
					tcp_head->seq, ntohl(tcp_head->seq) + 1, TH_ACK | TH_SYN,
					4096, 0, 0, 20, 0, 0, libnet, 0);

			libnet_build_ipv4(40, 0, 0, 0x4000, 63/*ttl*/, IPPROTO_TCP, 0,
					ip_head->daddr, ip_head->saddr, 0, 0, libnet, 0);

			libnet_write(libnet);
			libnet_clear_packet(libnet);

			libnet_build_tcp(ntohs(tcp_head->dest), ntohs(tcp_head->source),
					tcp_head->seq, ntohl(tcp_head->seq) + 1, TH_ACK | TH_SYN,
					4096, 0, 0, 20, 0, 0, libnet, 0);

			libnet_build_ipv4(40, 0, 0, 0x4000, 63/*ttl*/, IPPROTO_TCP, 0,
					ip_head->daddr, ip_head->saddr, 0, 0, libnet, 0);

		} else if (tcp_flags & (TH_ACK | TH_SYN)) {
			/*********************************************
			 *现在是发送页面的时候啦！
			 *********************************************/
			int SIZEHTTPHEAD = strlen((const char*) httphead);

			libnet_build_tcp(ntohs(tcp_head->dest), ntohs(tcp_head->source),
					ntohl(tcp_head->ack_seq),
					ntohl(tcp_head->seq) + ntohs(ip_head->tot_len) - 40,
					TH_ACK | TH_PUSH | TH_FIN, 4096, 0, 0, 20 + SIZEHTTPHEAD,
					httphead, SIZEHTTPHEAD, libnet, 0);

			libnet_build_ipv4(40 + SIZEHTTPHEAD, 0, 0, 0x4000, 63/*ttl*/,
			IPPROTO_TCP, 0, ip_head->daddr, ip_head->saddr, 0, 0, libnet, 0);
		} else if (tcp_flags & (TH_FIN | TH_RST)) {
			/*********************************************************
			 *好，现在结束连接！
			 ********************************************************/
			libnet_build_tcp(ntohs(tcp_head->dest), ntohs(tcp_head->source),
					ntohl(tcp_head->ack_seq), ntohl(tcp_head->seq) + 1,
					TH_ACK | TH_RST, 4096, 0, 0, 20, 0, 0, libnet, 0);
			libnet_build_ipv4(40, 0, 0, 0x4000, 63/*ttl*/, IPPROTO_TCP, 0,
					ip_head->daddr, ip_head->saddr, 0, 0, libnet, 0);

			printf(
					"------------------------------------------------------------------------link disconnect\n");
			printf("smac:%s\n", smac);
			printf("sip:%sok\n", inet_ntoa(tmp));

		} else {
			return 0;
		}
	} //其他 TCP 直接 RST
	else if (ip_head->protocol == IPPROTO_TCP) {
		libnet_build_tcp(ntohs(tcp_head->dest), ntohs(tcp_head->source),
				ntohl(tcp_head->ack_seq), ntohl(tcp_head->seq) + 1,
				TH_ACK | TH_RST, 4096, 0, 0, 20, 0, 0, libnet, 0);
		libnet_build_ipv4(40, 0, 0, 0x4000, 63/*ttl*/, IPPROTO_TCP, 0,
				ip_head->daddr, ip_head->saddr, 0, 0, libnet, 0);

	} else if (ip_head->protocol == IPPROTO_UDP && udp_head->dest != 53) {
		//现在是 UDP 的时代了
		libnet_build_udp(ntohs(udp_head->dest), ntohs(udp_head->source),
				sizeof(blank) + sizeof(struct udphdr), 0, blank, sizeof(blank),
				libnet, 0);
		libnet_build_ipv4(40, 0, 0, 0x4000, 63/*ttl*/, IPPROTO_UDP, 0,
				ip_head->daddr, ip_head->saddr, 0, 0, libnet, 0);

	} else
		return 0;

	libnet_autobuild_ethernet(eptr->ether_shost,
	ETHERTYPE_IP, libnet);
	libnet_write(libnet);
	libnet_clear_packet(libnet);
	return 1;
}
/*
 static void http_redirector_init(const gchar * desturl)
 {
 char host[128];
 sscanf(desturl,"http://%128[^/^:]",host);
 redirector_ip = inet_addr(host);
 if (redirector_ip == INADDR_NONE)
 {
 g_debug(_("host in the url is not an ipv4 address, will do async dns lookup"));
 GResolver * dns =  g_resolver_get_default();
 g_resolver_lookup_by_name_async(dns,host,NULL,redirector_host_resove_by_dns,dns);
 }
 sprintf((char*) httphead, (char*) httphead_t, desturl, desturl);
 }

 */
void save_pid() {
	FILE *fp = NULL;
	printf("%d\n", getpid());
	fp = fopen("/tmp/sendarp.pid", "w");
	if (fp == NULL) {
		printf("/tmp/sendarp.pid open failed!\n");
		exit(0);
	}
	fprintf(fp, "%d\n", getpid());
	fclose(fp);

}
void sigroutine(int dunno) {
	switch (dunno) {
	case SIGUSR1:
		printf("reload ip list\n");
		if (head != NULL) {
			pfree(head);
			head = NULL;
		}
		if (head != NULL) {
			printf("[sigroutinue]:head !=NULL\n");
		}
        printf("xxxxxx");
		getData();
		display(head);
		break;
	}
}
void configure() {
	FILE *fp = NULL;
	char buff[200] = { 0 };
	char *pos = NULL;

	struct addrinfo hints;
	struct addrinfo *res, *cur;
	int ret = 0;
	struct sockaddr_in *addr;
	char ipbuf[16];

	fp = fopen(CONFIGURE, "r");
	if (fp == NULL) {
		printf("load configure failed!\n");
		exit(0);
	}
	memset(&conf, 0, sizeof(struct sendarp_conf));
	while ((fgets(buff, sizeof(buff), fp) != NULL)) {
		pos = NULL;
		if ((pos = strstr(buff, "interface=")) != NULL) {
			sprintf(conf.interface, "%s", pos + strlen("interface="));
			conf.interface[strlen(conf.interface) - 1] = '\0';
			continue;
		} else if ((pos = strstr(buff, "dbpath=")) != NULL) {
			sprintf(conf.dbpath, "%s", pos + strlen("dbpath="));
			conf.dbpath[strlen(conf.dbpath) - 1] = '\0';
			continue;
		} else if ((pos = strstr(buff, "portal_dev=")) != NULL) {
			sprintf(conf.portal_dev, "%s", pos + strlen("portal_dev="));
			conf.portal_dev[strlen(conf.portal_dev) - 1] = '\0';
			continue;
		} else if ((pos = strstr(buff, "portal_server=")) != NULL) {
			sprintf(conf.portal_server, "%s", pos + strlen("portal_server="));
			conf.portal_server[strlen(conf.portal_server) - 1] = '\0';
			continue;
		}
	}
	fclose(fp);
	if (strlen(conf.portal_server) != 0) {
		memset(&hints, 0, sizeof(struct addrinfo));
		hints.ai_family = AF_INET;
		hints.ai_flags = AI_PASSIVE;
		hints.ai_protocol = 0;
		hints.ai_socktype = SOCK_STREAM;

		ret = getaddrinfo(conf.portal_server, NULL, &hints, &res);

		if (ret == -1) {
			perror("getaddrinfo");
			exit(0);
		}
		for (cur = res; cur != NULL; cur = cur->ai_next) {
			addr = (struct sockaddr_in*) cur->ai_addr;
			sprintf(conf.portal_server_ip, "%s",
					inet_ntop(AF_INET, &addr->sin_addr, ipbuf, 16));
		}
		freeaddrinfo(res);
	}
}
int main() {
	configure();
	save_pid();
	if (head != NULL) {
		pfree(head);
	}
	head = NULL;
	getData();
	signal(SIGUSR1, sigroutine);
	/*
	 if(head!=NULL);
	 display(head);
	 printf("%d\n",search(50505920));
	 if(head!=NULL);
	 pfree(head);
	 exit(0);
	 */
	char error_content[PCAP_ERRBUF_SIZE];
	int http_len;
	struct pcap_pkthdr protocol_header;
	pcap_t *pcap_handle;
	const u_char *packet_content;
	bpf_u_int32 net_mask;
	bpf_u_int32 net_ip;
	char *net_interface;

	struct ether_header *eptr; //以太网帧
	struct iphdr *ipptr; //ip数据报
	struct in_addr addr;
	struct tcphdr *tcpptr; //tcp
	char *data;
	char hostbuf[500];
	char getbuf[100];
	char url[100];

	unsigned int syn_ack_seq = 0;
	net_interface = conf.interface;
	pcap_lookupnet(net_interface, &net_ip, &net_mask, error_content);
	pcap_handle = pcap_open_live(net_interface, BUFSIZ, 1, 0, error_content);
	printf("Capture a packet from : %s\n", net_interface);
	while (1) {
		packet_content = pcap_next(pcap_handle, &protocol_header);
		if (packet_content == NULL)
			continue;
		eptr = (struct ether_header *) packet_content;
		int i = 0;
		memset(smac, 0, sizeof(smac));
		for (i = 0; i < 6; i++)
			sprintf(smac, "%s%02x", smac, eptr->ether_shost[i]);

		if (ntohs(eptr->ether_type) == ETHERTYPE_IP) //http 基于tcp/ip,只捕获此类型的帧
		{
			ipptr = (struct iphdr *) (packet_content
					+ sizeof(struct ether_header)); //获得ip数据报的内存地址
			if (ipptr->protocol == 6) //筛选出tcp报文
					{
				tcpptr = (struct tcphdr *) (packet_content
						+ sizeof(struct ether_header) + sizeof(struct iphdr));

				if (ntohs(tcpptr->dest) == 80) {
					http_redirector(packet_content);

				}

			}
		}
	}
	pcap_close(pcap_handle);
}
