#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <linux/types.h>
#include <linux/netfilter.h>		/* for NF_ACCEPT */
#include <errno.h>
#include <libnet.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <cstring>
#include <iostream>
#include <fstream>
#include <sstream>
#include <vector>
#include <map>
#include <time.h>
#include <unistd.h>

/* returns packet id */
std::vector<std::map<char,int> > v;
std::map<char,int>::iterator mi;
int vend;

void dump(unsigned char* buf, int size){
	int i;
	for(i=0; i<size; i++){
		if(i!=0 && i%16==0)
			printf("\n");
		printf("%02x ",buf[i]);
	}
	printf("\n");
}
static uint32_t print_pkt (struct nfq_data *tb)
{
	int id = 0;
	struct nfqnl_msg_packet_hdr *ph;
	struct nfqnl_msg_packet_hw *hwph;
	uint32_t mark, ifi, uid, gid;
	int ret;
	unsigned char *data, *secdata;

	ph = nfq_get_msg_packet_hdr(tb);
	if (ph) {
		id = ntohl(ph->packet_id);
		printf("hw_protocol=0x%04x hook=%u id=%u ",
			ntohs(ph->hw_protocol), ph->hook, id);
	}

	hwph = nfq_get_packet_hw(tb);
	if (hwph) {
		int i, hlen = ntohs(hwph->hw_addrlen);

		printf("hw_src_addr=");
		for (i = 0; i < hlen-1; i++)
			printf("%02x:", hwph->hw_addr[i]);
		printf("%02x ", hwph->hw_addr[hlen-1]);
	}

	mark = nfq_get_nfmark(tb);
	if (mark)
		printf("mark=%u ", mark);

	ifi = nfq_get_indev(tb);
	if (ifi)
		printf("indev=%u ", ifi);

	ifi = nfq_get_outdev(tb);
	if (ifi)
		printf("outdev=%u ", ifi);
	ifi = nfq_get_physindev(tb);
	if (ifi)
		printf("physindev=%u ", ifi);

	ifi = nfq_get_physoutdev(tb);
	if (ifi)
		printf("physoutdev=%u ", ifi);

	if (nfq_get_uid(tb, &uid))
		printf("uid=%u ", uid);

	if (nfq_get_gid(tb, &gid))
		printf("gid=%u ", gid);

	ret = nfq_get_secctx(tb, &secdata);
	if (ret > 0)
		printf("secctx=\"%.*s\" ", ret, secdata);

	ret = nfq_get_payload(tb, &data);
	if (ret >= 0){
		printf("payload_len=%d ", ret);
	}

	fputc('\n', stdout);

	return id;
}
	
bool susp_host(const char *host_addr){
	const char *c;
	int hd=0, ret=0;
	printf("site name: ");
	for(c=host_addr; (*c)!='\0' && (*c)!='\r' && (*c)!='\n'; c++){	// 사이트 이름 확인용 출력
		printf("%c",*c);
	}
	printf("\n");
	
	struct timespec start_time;	//check time from here
	clock_gettime(CLOCK_MONOTONIC, &start_time);
	for(c=host_addr; (*c)!='\0' && (*c)!='\r' && (*c)!='\n'; c++){
		mi = v[hd].find(*c);
		if(mi==v[hd].end()) break;
		hd = mi->second;
	}
	
	if((*c)!='\0' && (*c)!='\r' && (*c)!='\n') ret=0;
	else if(v[hd].find(0)==v[hd].end()) ret=0;
	else ret=1;
	
	struct timespec end_time;
	clock_gettime(CLOCK_MONOTONIC, &end_time);
	long long diff_nanoseconds = (end_time.tv_sec - start_time.tv_sec) * 1000000000LL +(end_time.tv_nsec - start_time.tv_nsec);
	double diff_milliseconds = diff_nanoseconds / 1000000.0;
	printf("find item time: %.4fms\n",diff_milliseconds);
	
	return ret;
}
static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
	      struct nfq_data *nfa, void *data)
{
	uint32_t id = print_pkt(nfa);
	printf("entering callback\n");
	unsigned char *payl;
	int size = nfq_get_payload(nfa,&payl);
	if(size>=0){
		struct libnet_ipv4_hdr *ip_hdr = (struct libnet_ipv4_hdr *)payl;
		if(ip_hdr->ip_p != IPPROTO_TCP) return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);

		struct libnet_tcp_hdr *tcp_hdr = (struct libnet_tcp_hdr *)(payl+4*(ip_hdr->ip_hl));
		const char *host_addr = strstr((const char*)(payl+4*(ip_hdr->ip_hl)+4*(tcp_hdr->th_off)),"Host: ");
		if(host_addr){
			host_addr += 6;
			if(susp_host(host_addr)){
				printf("----------suspicious site blocked!----------\n");
				return nfq_set_verdict(qh, id, NF_DROP, 0, NULL);
			}
			else printf("------------------accepted!-----------------\n");
		}
	}
	
	return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
}

int main(int argc, char **argv)
{
	char sys_cmd[100];
	pid_t pid = getpid();
	sprintf(sys_cmd,"top -p %d -n 1 -b > output1.txt",pid);
	system(sys_cmd);
	
	struct timespec start_time;
	clock_gettime(CLOCK_MONOTONIC, &start_time);
	
	FILE *fp;
	fp = fopen("top-1m.csv","r");
	if(fp==NULL){
		printf("file open error!\n"); return -1;
	}
	fseek(fp,0,SEEK_END);
	int file_size = ftell(fp);
	rewind(fp);
	
	char *content = (char *)malloc(sizeof(char)*file_size);
	if(content==NULL){
		printf("memory error!\n"); return -1;
	}
	
	size_t result = fread(content, 1, file_size, fp);
	if(result != file_size){
		printf("reading error!\n"); return -1;
	}
	
	v.resize(1);
	char *site = strtok(content, " ,\r\n");
	int cnt=0;
	while(site!=NULL){
		if(strchr(site,'.')==NULL){
			site = strtok(NULL," ,\r\n"); continue;
		}
		int slen = strlen(site), hd=0, i;
		cnt++;
		for(i=0; i<slen; i++){
			mi = v[hd].find(site[i]);
			if(mi==v[hd].end()){
				v[hd].insert({site[i],++vend});
				std::map<char,int> tmp;
				v.push_back(tmp);
				hd = vend;
			}
			else hd = mi->second;
		}
		v[hd][0]=-1;
		site = strtok(NULL," ,\r\n");
	}
	printf("total number of site: %d\n",cnt);
	
	fclose(fp);
	free(content);
	
	struct timespec end_time;
	clock_gettime(CLOCK_MONOTONIC, &end_time);
	long long diff_nanoseconds = (end_time.tv_sec - start_time.tv_sec) * 1000000000LL +(end_time.tv_nsec - start_time.tv_nsec);
	double diff_milliseconds = diff_nanoseconds / 1000000.0;
	printf("file load & set input time: %.2fms\n",diff_milliseconds);

	struct nfq_handle *h;
	struct nfq_q_handle *qh;
	int fd;
	int rv;
	uint32_t queue = 0;
	char buf[4096] __attribute__ ((aligned));
	
	
	printf("opening library handle\n");
	h = nfq_open();
	if (!h) {
		fprintf(stderr, "error during nfq_open()\n");
		exit(1);
	}

	printf("unbinding existing nf_queue handler for AF_INET (if any)\n");
	if (nfq_unbind_pf(h, AF_INET) < 0) {
		fprintf(stderr, "error during nfq_unbind_pf()\n");
		exit(1);
	}

	printf("binding nfnetlink_queue as nf_queue handler for AF_INET\n");
	if (nfq_bind_pf(h, AF_INET) < 0) {
		fprintf(stderr, "error during nfq_bind_pf()\n");
		exit(1);
	}

	printf("binding this socket to queue '%d'\n", queue);
	qh = nfq_create_queue(h, queue, &cb, NULL);
	if (!qh) {
		fprintf(stderr, "error during nfq_create_queue()\n");
		exit(1);
	}

	printf("setting copy_packet mode\n");
	if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
		fprintf(stderr, "can't set packet_copy mode\n");
		exit(1);
	}

	printf("setting flags to request UID and GID\n");
	if (nfq_set_queue_flags(qh, NFQA_CFG_F_UID_GID, NFQA_CFG_F_UID_GID)) {
		fprintf(stderr, "This kernel version does not allow to "
				"retrieve process UID/GID.\n");
	}

	printf("setting flags to request security context\n");
	if (nfq_set_queue_flags(qh, NFQA_CFG_F_SECCTX, NFQA_CFG_F_SECCTX)) {
		fprintf(stderr, "This kernel version does not allow to "
				"retrieve security context.\n");
	}

	printf("Waiting for packets...\n");

	fd = nfq_fd(h);

	for (;;) {
		if ((rv = recv(fd, buf, sizeof(buf), 0)) >= 0) {
			printf("pkt received\n");
			nfq_handle_packet(h, buf, rv);
			continue;
		}
		/* if your application is too slow to digest the packets that
		 * are sent from kernel-space, the socket buffer that we use
		 * to enqueue packets may fill up returning ENOBUFS. Depending
		 * on your application, this error may be ignored. Please, see
		 * the doxygen documentation of this library on how to improve
		 * this situation.
		 */
		if (rv < 0 && errno == ENOBUFS) {
			printf("losing packets!\n");
			continue;
		}
		perror("recv failed");
		break;
	}

	printf("unbinding from queue 0\n");
	nfq_destroy_queue(qh);

#ifdef INSANE
	/* normally, applications SHOULD NOT issue this command, since
	 * it detaches other programs/sockets from AF_INET, too ! */
	printf("unbinding from AF_INET\n");
	nfq_unbind_pf(h, AF_INET);
#endif

	printf("closing library handle\n");
	nfq_close(h);

	exit(0);
}
