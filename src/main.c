#include <stdio.h>
#include <string.h>

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

#include <signal.h>
#include "md5.h"
#define CONFIGURE "/etc/sendarp.conf"
#define SENDARP_PID "/tmp/sendarp.pid"

struct sendarp_conf {
	char interface[20];
	char dbpath[50];
	char portal_dev[50];
	char portal_server[50];
	char portal_server_ip[16];
	char portal_server_ip_num; // youhua
} conf;
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
	char token[100] = { 0 };
	char portal_server[20] = { 0 };
	char sip[20] = { 0 };
	char smac[20] = { 0 };
	char *str = getenv("QUERY_STRING");
	char encrypt[50] = { 0 };
	unsigned char decrypt[16] = { 0 };
	int i = 0;
	char token_verify[100] = { 0 };

	int nRow;
	int nColumn;
	sqlite3 *db;
	char *zErrMsg;
	char **azResult;
	char sql[100] = { 0 };
	int rt = 0;

	FILE *fp = NULL;
	char buff[100];
	unsigned int sendarp_pid = 0;

	printf("Content-type:text/html\n\n");
	printf("<html>");
	printf("<head><title>welcome to c cgi.</title></head><body>");
	printf("str:%s\n", str);
	if (str != NULL)
		sscanf(str, "token=%[^&]&sip=%[^&]&smac=%[^&]", token, sip, smac);
	printf("<br>");
	printf("token:%s\n", strlen(token) == 0 ? "" : token);
	printf("sip:%s\n", strlen(sip) == 0 ? "" : sip);
	printf("smac:%s\n", strlen(smac) == 0 ? "" : smac);

	printf("</body></html>");
	sprintf(encrypt, "%sadmin", "192.168.2.3");

	MDString(encrypt, decrypt);
	for (i = 0; i < 16; i++) {

		sprintf(token_verify, "%s%02x", token_verify, decrypt[i]);
	}

	//	printf("%s\n",token_verify);
//	if (strcmp(token, token_verify) != 0) {
//		goto failed;
//	}
	if (sqlite3_open(conf.dbpath, &db)) {
		printf("%s", sqlite3_errmsg(db));
		exit(0);
	}
	sprintf(sql, "select * from portal where sip='%s'", sip);
	printf("sql:%s<br>", sql);
	printf("conf.dbpath:%s<br>", conf.dbpath);
	rt = sqlite3_get_table(db, sql, &azResult, &nRow, &nColumn, &zErrMsg);
	printf("rt:%d<br>", rt);
	printf("nRow:%d<br>", rt);
	sqlite3_free_table(azResult);
	sqlite3_free(zErrMsg);
	if (nRow == 0) {
		sprintf(sql, "insert into portal(sip,smac) values('%s','%s')", sip,
				smac);
		printf("sql:%s<br>", sql);

		rt = sqlite3_exec(db, sql, 0, 0, &zErrMsg);
		if (rt != SQLITE_OK) {
			sqlite3_close(db);
			printf("%s\n", zErrMsg);
			sqlite3_free(zErrMsg);
		}
		printf("rt:%d<br>", rt);
		if ((db != NULL)) {
			sqlite3_close(db);
			sqlite3_free(zErrMsg);
		}
		fp = fopen(SENDARP_PID, "r");
		if (fp == NULL) {
			printf("%s open failed\n", SENDARP_PID);
			exit(0);
			goto failed;
		}
		fread(buff, sizeof(buff), 1, fp);
		sendarp_pid = strtol(buff, NULL, 10);
		fclose(fp);
		if (sendarp_pid != 0) {
			kill(sendarp_pid, SIGUSR1);
			kill(sendarp_pid, SIGUSR1);
		} else {
			goto failed;
		}
		printf("kill pid %d<br>", sendarp_pid);
		goto success;
	} else {
		printf("ip existed<br>");
		goto success;
	}

	if ((db != NULL)) {
		sqlite3_close(db);
		sqlite3_free(zErrMsg);
	}
	goto success;

	success: printf(
			"<script language=\"javascript\">\
 window.location.href=\"http://%s:5246/test/success.jsp\";\
</script>",
			conf.portal_server);
	printf("</body></html>");
	failed: printf(
			"<script language=\"javascript\">\
 window.location.href=\"http://www.baidu.com\";\
</script>");
	printf("</body></html>");

}
