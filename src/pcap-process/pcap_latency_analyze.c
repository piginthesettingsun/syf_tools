#include<stdio.h>
#include<string.h>
#include<stdlib.h>
#include<stdint.h>

#include <linux/if_ether.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip.h>
#include <netinet/in.h>
/******************************************************************************/
#define PATH_OUTPUT	"out.txt"
/******************************************************************************/
// pcap structs
struct pcap_file_header
{
	uint32_t magic;
	uint16_t version_major;
	uint16_t version_minor;
	uint32_t thiszone;
	uint32_t sigfigs;
	uint32_t snaplen;
	uint32_t linktype;
};

typedef struct pcap_timestamp
{
	uint32_t ts_sec;
	uint32_t ts_usec;
} pts_t;

struct pcap_header
{
	pts_t ts;
	uint32_t capture_len;
	uint32_t len;
};
/*----------------------------------------------------------------------------*/
// delay analyze structs
typedef struct record
{
	uint32_t req_seq;
	pts_t ts_req;
} record_t;

#define STREAM_TABLE_SIZE 100000
typedef struct stream_table
{
	record_t record[STREAM_TABLE_SIZE];
} stream_table_t;

typedef struct delay_list
{
	int count;
	uint64_t ts[1000000];
	uint64_t delays[1000000];
} delay_list_t;
/******************************************************************************/
pts_t ts_start={0};
/******************************************************************************/
static inline uint64_t
get_interval(pts_t *ts1, pts_t *ts2)
{
	return (uint64_t)(ts2->ts_sec - ts1->ts_sec)*1000000 + 
			ts2->ts_usec-ts1->ts_usec;
}

static inline uint64_t
get_relative_ts(pts_t *cur_ts)
{
	if ((ts_start.ts_usec == 0 && ts_start.ts_sec==0)) {
		ts_start.ts_sec = cur_ts->ts_sec;
		ts_start.ts_usec = cur_ts->ts_usec;
		return 0;
	}
	return get_interval(&ts_start, cur_ts);
}

// return the mid of (left, mid, right), and swap to the left
static inline void
get_mid(uint64_t a[], int l, int r)
{
	int m = (l + r)/2;
	int i;

	if (a[l] < a[m]) {
		// l<m
		if (a[m] < a[r]) {
			// l<m<r
			i = m;
		} else {
			// r<m
			if (a[l] < a[r]) {
				// l<r<m
				i = r;
			} else {
				// r<l<m
				i = l;
			}
		}
	} else {
		// m<l
		if (a[r] < a[m]) {
			// r<m<l
			i = m;
		} else {
			// m<r
			if (a[r] < a[l]) {
				// m<r<l
				i = r;
			} else {
				// m<l<r
				i = l;
			}
		}
	}
	if (i == l ) {
		return;
	}
	uint64_t temp = a[i];
	a[i] = a[l];
	a[l] = temp;
}

static void
sort(uint64_t a[], int left, int right)
{
	if (left >= right) {
		return;
	}

	int i = left;
	int j = right;
	get_mid(a, left, right);
	uint64_t key = a[left];	// make a hole at left
	
	while (i < j) {
		while (i<j&&a[j]>key) {
			j--;
		}
		if (i < j) {
			a[i++] = a[j];
		}
		while (i < j&&a[i] < key) {
			i++;
		}
		if (i < j) {
			a[j--] = a[i];
		}
	}
	a[i] = key; // i==j, pointing to the hole

	sort(a, left, i - 1);
	sort(a, i + 1, right);
}
/*----------------------------------------------------------------------------*/
// delay analyze functions
static inline int
add_delay_item(delay_list_t *delays, uint64_t delay, uint64_t ts)
{
	delays->ts[delays->count] = ts;
	delays->delays[delays->count++] = delay;
}
	
static inline int
process_req(pts_t *ts, uint16_t port, uint32_t req_cnt, stream_table_t *streams)
{
	record_t *record = &streams->record[port];
	if (record->req_seq == req_cnt) {
		// duplicate request
		return 0;
	}
	record->req_seq = req_cnt;
	record->ts_req = *ts;
}

static inline int
process_rsp(pts_t *ts, uint16_t port, uint32_t req_cnt, stream_table_t *streams, 
		delay_list_t *delays)
{
	record_t *record = &streams->record[port];
	if (record->req_seq != req_cnt) {
		// unorderd response
		return 0;
	}
	uint64_t delay = get_interval(&record->ts_req, ts);
	add_delay_item(delays, delay, get_relative_ts(&record->ts_req));
}

static inline int
print_sorted_result(delay_list_t *delays)
{
	int num = 11;
	int i, index;
	double proportions[] = {0, 0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 0.99};
	sort(delays->delays, 0, delays->count-1);
	fprintf(stdout, "result from %d requests:\n"
			"proportion\t delay\n");
	for (i=0; i<num; i++) {
		index = (uint64_t)(proportions[i] * (delays->count-1));
		fprintf(stdout, "%lf\t\t %llu\n", proportions[i], delays->delays[index]);
	}
}

static inline void
print_ts_result(delay_list_t *delays)
{
	int i;
	uint64_t ts;
	for (i=0; i<delays->count; i++) {
		fprintf(stdout, "%llu %llu\n", delays->ts[i], delays->delays[i]);
	}
}
/*----------------------------------------------------------------------------*/
// packet process functions
static inline int
process_tcp_pkt(pts_t *ts, char *tcp_data, int ip_len, stream_table_t *streams, 
		delay_list_t *delays)
{
	struct tcphdr *tcph = (struct tcphdr *)tcp_data;
	int tcp_header_len = tcph->doff <<2;
	uint8_t *payload = tcp_data + tcp_header_len;
	int payloadlen = ip_len - 20 - tcp_header_len;
	uint16_t port_src = ntohs(tcph->source);
	uint16_t port_dst = ntohs(tcph->dest);
	int i;
	int rsp_num;
	uint8_t priority = 0;

	if (!payload) {
		return 0;
	}
	

	rsp_num = payloadlen/30;
	for (i=0; i<rsp_num; i++) {
		if (payload[5 + 30*i] == 0x1) {
			priority = 1;
			break;
		}
	}
	if (priority == 0) {
		return 0;
	}

	uint32_t req_cnt = *((uint32_t *)(payload+ 30*i));
	if (port_dst == 80) {
		// request
		process_req(ts, port_src, req_cnt, streams);
	} else if (port_src == 80) {
		// response
		process_rsp(ts, port_dst, req_cnt, streams, delays);
	}
}
/******************************************************************************/
static inline int 
pcap_get_delay(FILE *file_in, delay_list_t *delays)
{
	static stream_table_t streams;
	struct pcap_file_header pfh;
	struct pcap_header ph;
	char pkt_data[2000];
	int i;
	int cnt = 0;
	
	fread(&pfh, sizeof(struct pcap_file_header), 1, file_in);
	for (i=0; i<STREAM_TABLE_SIZE; i++) {
		streams.record[i].req_seq = -1;
	}

	while (fread(&ph, sizeof(struct pcap_header), 1, file_in) == 1) {
		cnt++;
		if (fread(pkt_data, ph.capture_len, 1, file_in) != 1) {
			fprintf(stderr, "[ERR]filed to read pkt!\n");
			continue;
		}
	
		struct ethhdr *ethh = (struct ethhdr *)pkt_data;
		uint16_t ip_proto = ntohs(ethh->h_proto);
		struct iphdr* iph; 
		if (ip_proto != ETH_P_IP) {
			// vlan packet
//			fprintf(stderr, "[ERR]not an IP pkt!\n");
//			continue;
			iph = (struct iphdr*)(pkt_data+sizeof(struct ethhdr) + 4);
		} else {
			iph = (struct iphdr*)(pkt_data+sizeof(struct ethhdr));
		}
		int ip_len = ntohs(iph->tot_len);
		if (iph->version != 0x4) {
			fprintf(stderr, "[ERR]invalid IP packet!\n");
			continue;
		}
		if (iph->protocol == IPPROTO_TCP) {
			process_tcp_pkt(&ph.ts, ((char *)iph)+20, ip_len, &streams, delays);
		}
	}
}

int 
main(int argc, char **argv)
{ 
	char *path_input = argv[1];
	FILE *file_in = fopen(path_input, "r");
//	FILE *file_out = fopen(PATH_OUTPUT, "w");

	static delay_list_t delays;
	delays.count = 0;
	pcap_get_delay(file_in, &delays);
	print_sorted_result(&delays);
	
	close(file_in);
//	close(file_out);
}
