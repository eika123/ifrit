// +build ignore

#include "vmlinux.h"
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#define TC_ACT_OK 0
#define ETH_P_IP 0x0800

#define IPPROTO_TCP 6
#define IPPROTO_UDP 17

// Configurable ports injected dynamically at runtime by Go via BPF .rodata
// constants in ELF file. Defaults are 9000 for TCP gossip and 9001 for UDP
// ping/pong.
volatile const __u16 gossip_tcp_port = 9000;
volatile const __u16 ping_udp_port = 9001;

#define MAX_PAYLOAD_SAMPLE_LEN 512

// Event submitted to user space via BPF RingBuffer
struct packet_event {
  __u64 timestamp_ns;
  __u32 src_ip;
  __u32 dst_ip;
  __u32 tcp_seq;
  __u32 tcp_ack_seq;
  __u16 src_port;
  __u16 dst_port;
  __u8 protocol;
  __u8 tcp_flags; // Bitmask of SYN, ACK, FIN, RST, PSH
  __u8 _pad[2];
  __u32 payload_len;
  __u8 payload[MAX_PAYLOAD_SAMPLE_LEN];
};

/**
 * @brief Converts network byte order (big-endian) 16-bit integers to host byte
 * order.
 *
 * Wraps bpf_ntohs() to provide a self-explanatory identifier for
 * network-to-host short conversions (typically 16-bit port numbers).
 *
 * @param val 16-bit integer in network byte order.
 * @return 16-bit integer in host byte order.
 */
static __always_inline __u16 bpf_network_to_host_short(__u16 val) {
  return bpf_ntohs(val);
}

/**
 * @brief Converts network byte order (big-endian) 32-bit integers to host byte
 * order.
 *
 * Wraps bpf_ntohl() to provide a self-explanatory identifier for
 * network-to-host long conversions (such as IPv4 addresses and TCP
 * sequence/acknowledgment numbers).
 *
 * @param val 32-bit integer in network byte order.
 * @return 32-bit integer in host byte order.
 */
static __always_inline __u32 bpf_network_to_host_long(__u32 val) {
  return bpf_ntohl(val);
}

// BPF RingBuffer map for lockless zero-copy streaming to user space
struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, 1 << 24); // 16 MB ring buffer
} events SEC(".maps");

// SEC("tc") is a program that is attached to the tc (traffic control)
// hook point, this tc hook is attached to the ingress interface of the node.
// https://docs.kernel.org/networking/skbuff.html
// The __sk_buff struct is the kernels representation of a network packet.
SEC("tc")
int tc_packet_filter(struct __sk_buff *socket_buffer) {
  // data_end is the memory boundary where the packet ends.
  void *data_end = (void *)(long)socket_buffer->data_end;

  // points to first byte of the packet in the ethernet frame
  void *data = (void *)(long)socket_buffer->data;

  // 1. Parse Ethernet Header
  struct ethhdr *ethernet_header = data;
  if ((void *)(ethernet_header + 1) > data_end) {
    return TC_ACT_OK;
  }

  // checks if the ethernet frame contains an IPv4 packet
  if (bpf_network_to_host_short(ethernet_header->h_proto) != ETH_P_IP) {
    return TC_ACT_OK;
  }

  // 2. Parse IPv4 Header
  struct iphdr *ip_header = (void *)(ethernet_header + 1);
  if ((void *)(ip_header + 1) > data_end) {
    return TC_ACT_OK;
  }

  // ihl is the ip header length, and we multiply it by 4 to get the
  // actual size of the ip header in bytes
  __u32 ip_hdr_len = ip_header->ihl * 4;
  if (ip_hdr_len < sizeof(struct iphdr)) {
    return TC_ACT_OK;
  }

  // l4_hdr is the header of the L4 protocol (TCP, UDP, etc.), that is
  // located at the start of the IPV4 payload
  void *l4_hdr = (void *)ip_header + ip_hdr_len;
  if (l4_hdr > data_end) {
    return TC_ACT_OK;
  }

  __u16 src_port = 0;
  __u16 dst_port = 0;
  __u32 payload_offset = 0;
  __u32 tcp_seq = 0;
  __u32 tcp_ack_seq = 0;
  __u8 tcp_flags = 0;
  __u8 protocol = ip_header->protocol;

  // Filter: only TCP traffic with Ifrit gossip port (configurable, default
  // 9000)
  if (protocol == IPPROTO_TCP) {
    struct tcphdr *tcp_header = l4_hdr;
    if ((void *)(tcp_header + 1) > data_end) {
      return TC_ACT_OK;
    }

    src_port = bpf_network_to_host_short(tcp_header->source);
    dst_port = bpf_network_to_host_short(tcp_header->dest);

    // Filter: only TCP traffic with Ifrit gossip port (configurable, default
    // 9000)
    if (src_port != gossip_tcp_port && dst_port != gossip_tcp_port) {
      return TC_ACT_OK;
    }

    // Extract sequence numbers for TCP retransmission tracking
    tcp_seq = bpf_network_to_host_long(tcp_header->seq);
    tcp_ack_seq = bpf_network_to_host_long(tcp_header->ack_seq);

    // Pack TCP control bits canonically per RFC 9293 Section 3.1:
    // Bits 100..107 in TCP header: [CWR, ECE, URG, ACK, PSH, RST, SYN, FIN]
    // https://datatracker.ietf.org/doc/html/rfc9293#section-3.1
    if (tcp_header->fin)
      tcp_flags |= (1 << 0);
    if (tcp_header->syn)
      tcp_flags |= (1 << 1);
    if (tcp_header->rst)
      tcp_flags |= (1 << 2);
    if (tcp_header->psh)
      tcp_flags |= (1 << 3);
    if (tcp_header->ack)
      tcp_flags |= (1 << 4);
    if (tcp_header->urg)
      tcp_flags |= (1 << 5);
    if (tcp_header->ece)
      tcp_flags |= (1 << 6);
    if (tcp_header->cwr)
      tcp_flags |= (1 << 7);

    // doff: Data offset: The number of 32-bit words in the TCP header.
    // It indicates where the payload begins. We multiply by 4 to get the
    // length in bytes. See
    // https://datatracker.ietf.org/doc/html/rfc9293#name-header-format.
    __u32 tcp_hdr_len = tcp_header->doff * 4;
    if (tcp_hdr_len < sizeof(struct tcphdr)) {
      return TC_ACT_OK;
    }
    payload_offset = sizeof(struct ethhdr) + ip_hdr_len + tcp_hdr_len;

  } else if (protocol == IPPROTO_UDP) {
    struct udphdr *udp = l4_hdr;
    if ((void *)(udp + 1) > data_end) {
      return TC_ACT_OK;
    }

    src_port = bpf_network_to_host_short(udp->source);
    dst_port = bpf_network_to_host_short(udp->dest);

    // Filter: only UDP traffic with Ifrit failure detector port (configurable,
    // default 9001)
    if (src_port != ping_udp_port && dst_port != ping_udp_port) {
      return TC_ACT_OK;
    }

    payload_offset = sizeof(struct ethhdr) + ip_hdr_len + sizeof(struct udphdr);
  } else {
    // other protocol - we are not interested.
    return TC_ACT_OK;
  }

  // Check payload bounds
  if (payload_offset > socket_buffer->len) {
    return TC_ACT_OK;
  }

  __u32 payload_len = socket_buffer->len - payload_offset;
  if (payload_len == 0) {
    // Pure ACK, SYN, or FIN control packet with no application data payload.
    // We skip sending empty control packets to user-space ring buffer.
    return TC_ACT_OK;
  }

  // Reserve ring buffer slot
  struct packet_event *event =
      bpf_ringbuf_reserve(&events, sizeof(struct packet_event), 0);
  if (!event) {
    return TC_ACT_OK;
  }

  event->timestamp_ns = bpf_ktime_get_ns();
  event->src_ip = ip_header->saddr;
  event->dst_ip = ip_header->daddr;
  event->tcp_seq = tcp_seq;
  event->tcp_ack_seq = tcp_ack_seq;
  event->src_port = src_port;
  event->dst_port = dst_port;
  event->protocol = protocol;
  event->tcp_flags = tcp_flags;
  event->_pad[0] = 0;
  event->_pad[1] = 0;
  event->payload_len = payload_len;

  __u32 sample_len = payload_len;
  if (sample_len > MAX_PAYLOAD_SAMPLE_LEN) {
    sample_len = MAX_PAYLOAD_SAMPLE_LEN;
  }

  // Copy payload using bpf_skb_load_bytes helper
  if (bpf_skb_load_bytes(socket_buffer, payload_offset, event->payload,
                         sample_len) < 0) {
    bpf_ringbuf_discard(event, 0);
    return TC_ACT_OK;
  }

  bpf_ringbuf_submit(event, 0);
  return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";
