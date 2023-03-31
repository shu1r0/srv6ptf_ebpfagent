
#include <stdbool.h>
#include <arpa/inet.h>
#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/in6.h>
#include <linux/seg6.h>
#include <linux/seg6_local.h>

#include <linux/pkt_cls.h>

#include "bpf_helpers.h"
#include "bpf_trace_helpers.h"

#define PKTID_TLV_TYPE 124
#define PKTID_TLV_NODEID_LEN 2  // 16 (bit)
#define PKTID_TLV_COUNTER_LEN 4 // 32 (bit)

#define COUNTER_INDEX 0
#define NODEID_INDEX 1

struct sr6_pktid_tlv
{
  __u8 type;
  __u8 len;
  unsigned char node_id[PKTID_TLV_NODEID_LEN];
  unsigned char counter[PKTID_TLV_COUNTER_LEN];
};

/**
 * @brief create new pktid tlv struct
 *
 * @param nodeid
 * @param counter
 * @return __always_inline struct*
 */
static __always_inline struct sr6_pktid_tlv new_pktid_tlv(__u16 nodeid, unsigned long counter)
{
  struct sr6_pktid_tlv tlv = {
      .type = (__u8)PKTID_TLV_TYPE,
      .len = (__u8)(PKTID_TLV_NODEID_LEN + PKTID_TLV_COUNTER_LEN)};
  nodeid = htons(nodeid);
  counter = htonl(counter);
  __builtin_memcpy(tlv.node_id, (char *)&nodeid, sizeof(tlv.node_id));
  __builtin_memcpy(tlv.counter, (char *)&counter, sizeof(tlv.counter));

  bpf_debug("pktid addr=%u", &tlv);

  return tlv;
}

static __always_inline unsigned long long countertoi(struct sr6_pktid_tlv *tlv, void *data_end)
{
  unsigned long long counter = 0;
#pragma clang loop unroll(full)
  for (int i = 0; i < PKTID_TLV_COUNTER_LEN; i++)
  {
    counter += tlv->counter[i] << (8 * (PKTID_TLV_COUNTER_LEN - i - 1));
  }
  return counter;
}

static __always_inline unsigned long long nodeidtoi(struct sr6_pktid_tlv *tlv)
{
  unsigned long long nodeid = 0;
#pragma clang loop unroll(full)
  for (int i = 0; i < PKTID_TLV_NODEID_LEN; i++)
  {
    nodeid += tlv->node_id[i] << (8 * (PKTID_TLV_NODEID_LEN - i - 1));
  }
  return nodeid;
}

// Perf Map
struct bpf_map_def SEC("maps") perf_map = {
    .type = BPF_MAP_TYPE_PERF_EVENT_ARRAY,
    .max_entries = 128,
};

// PerfEvent item
//
// Set `unused` to specify the type in bpf2go.
// Optimization methods are different between C structures and Go structures.
// When converting a structure, padding is performed, and the conversion may not be successful.
// Therefore, it is necessary to inform the type to be converted using type.
// cf. https://github.com/cilium/ebpf/issues/821
struct perf_event_item
{
  __u64 pktid;               // 8 bytes
  __u64 monotonic_timestamp; // 8 bytes
  __u8 hookpoint;            // 1 btyes
} __attribute__((packed));
struct perf_event_item *unused_event __attribute__((unused));

// Config Map
// 0: None
// 1: NodeId
struct bpf_map_def SEC("maps") config_map = {
    .type = BPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(__u32),
    .value_size = sizeof(__u32),
    .max_entries = 32,
    // .map_flags = 0,
};

// Counter Map
struct bpf_map_def SEC("maps") counter_map = {
    .type = BPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(__u32),
    .value_size = sizeof(__u32),
    .max_entries = 32,
    // .map_flags = 0,
};

/**
 * @brief parse Segment Routing Header (SRH)
 *
 * @param data
 * @param data_end
 * @return __always_inline struct*
 */
static __always_inline struct ipv6_sr_hdr *get_srh(void *data, void *data_end)
{
  struct ethhdr *eth;
  struct iphdr *ip;
  struct ipv6hdr *ipv6;
  struct ipv6_sr_hdr *srh;

  if (data < data_end)
  {
    // L2
    eth = data;
    if ((void *)eth + sizeof(*eth) > data_end)
    {
      return NULL;
    }

    // L3
    switch (__constant_htons(eth->h_proto))
    {
    case ETH_P_IP:
      ip = data + sizeof(*eth);
      if ((void *)ip + sizeof(*ip) > data_end)
      {
        return NULL;
      }
      return NULL;
      break;
    case ETH_P_IPV6:
      ipv6 = data + sizeof(*eth);
      if ((void *)ipv6 + sizeof(*ipv6) > data_end)
      {
        return NULL;
      }

      if (ipv6->nexthdr == IPPROTO_ROUTING)
      {
        srh = data + sizeof(*eth) + sizeof(*ipv6);
        if ((void *)srh + sizeof(*srh) > data_end)
        {
          return NULL;
        }
        return srh;
      }
      break;
    default:
      break;
    }
  }
  return NULL;
}

/**
 * @brief Get the pktidtlv object
 *
 * @param srh
 * @return __always_inline struct*
 */
static __always_inline struct sr6_pktid_tlv *get_pktidtlv(struct ipv6_sr_hdr *srh, void *data, void *data_end)
{
  // SRH length including header (bytes)
  int len = (srh->hdrlen + 1) << 3;
  // srh header length + segment list length(= segment number * ipv6address length(16 bytes))
  unsigned int tlv_offset = sizeof(*srh) + (srh->first_segment + 1) * sizeof(struct in6_addr);
  int trailing = len - tlv_offset;

#pragma clang loop unroll(full)
  for (int i = 0; i < 4; i++)
  {
    struct sr6_tlv *tlv;
    unsigned int tlv_len;

    if (trailing < sizeof(*tlv))
      return NULL;

    tlv = (void *)srh + tlv_offset;
    if ((void *)tlv + sizeof(*tlv) > data_end)
    {
      return NULL;
    }

    // is pktid tlv?
    if (tlv->type == PKTID_TLV_TYPE)
    {
      struct sr6_pktid_tlv *pktid_tlv = tlv;
      if ((void *)pktid_tlv + sizeof(*pktid_tlv) + sizeof(pktid_tlv->node_id) + sizeof(pktid_tlv->counter) > data_end)
      {
        return NULL;
      }
      return pktid_tlv;
    }

    tlv_len = sizeof(*tlv) + tlv->len;
    trailing -= tlv_len;
    if (trailing < 0)
    {
      return NULL;
    }
    tlv_offset += tlv_len;
  }
  return NULL;
}

static __always_inline bool update_pkt_len(struct ipv6hdr *ipv6, struct ipv6_sr_hdr *srh, int size)
{
  ipv6->payload_len += htons(size);
  srh->hdrlen += size / 8;
  return true;
}

/**
 * @brief push the pktidTLV
 *
 * @param data
 * @param data_end
 * @param pktid
 * @return __always_inline
 */
static __always_inline bool push_pktidtlv_xdp(struct xdp_md *ctx, int nodeid, int counter)
{
  struct sr6_pktid_tlv pktid_tlv = new_pktid_tlv(nodeid, counter);

  // change packet size
  if (bpf_xdp_adjust_head(ctx, 0 - (int)sizeof(pktid_tlv)) != 0)
  {
    return false;
  }

  void *data_end = (void *)(long)ctx->data_end;
  void *data = (void *)(long)ctx->data;

  // Ethernet
  struct ethhdr *new_eth = data;
  struct ethhdr *old_eth = data + sizeof(pktid_tlv);
  struct ethhdr tmp_eth;
  if ((void *)new_eth + sizeof(*new_eth) > data_end || (void *)old_eth + sizeof(*old_eth) > data_end)
  {
    return false;
  }
  __builtin_memcpy(&tmp_eth, old_eth, sizeof(*old_eth));
  // __builtin_memcpy(new_eth, &tmp_eth, sizeof(tmp_eth));

  // IPv6 Header
  struct ipv6hdr *new_ipv6 = (void *)new_eth + sizeof(*new_eth);
  struct ipv6hdr *old_ipv6 = (void *)new_ipv6 + sizeof(pktid_tlv);
  struct ipv6hdr tmp_ipv6;
  if (((void *)new_ipv6 + sizeof(*new_ipv6) > data_end) || ((void *)old_ipv6 + sizeof(*old_ipv6) > data_end))
  {
    return false;
  }
  __builtin_memcpy(&tmp_ipv6, old_ipv6, sizeof(tmp_ipv6));
  // __builtin_memcpy(new_ipv6, &tmp_ipv6, sizeof(*new_ipv6));

  // SRH
  struct ipv6_sr_hdr *new_srh = (void *)new_ipv6 + sizeof(*new_ipv6);
  struct ipv6_sr_hdr *old_srh = (void *)new_srh + sizeof(pktid_tlv);
  struct ipv6_sr_hdr tmp_srh;
  unsigned long segments_size = (old_srh->first_segment + 1) * sizeof(struct in6_addr);
  if ((void *)new_srh + sizeof(*new_srh) > data_end || (void *)old_srh + sizeof(*old_srh) > data_end)
  {
    return false;
  }
  __builtin_memcpy(&tmp_srh, old_srh, sizeof(tmp_srh));
  // __builtin_memcpy(new_srh, &tmp_srh, sizeof(*new_srh));

  // New TLV space
  struct sr6_pktid_tlv *new_pktid_tlv = (void *)new_srh + sizeof(*new_srh) + segments_size;
  if ((void *)new_pktid_tlv + sizeof(*new_pktid_tlv) > data_end)
  {
    return false;
  }
  // __builtin_memcpy(new_pktid_tlv, pktid_tlv, sizeof(pktid_tlv));

  __builtin_memcpy(new_eth, &tmp_eth, sizeof(tmp_eth));
  __builtin_memcpy(new_ipv6, &tmp_ipv6, sizeof(*new_ipv6));
  __builtin_memcpy(new_srh, &tmp_srh, sizeof(*new_srh));

  // copy segment list
  for (int i = 0; i < 15; i++)
  {
    if (i < new_srh->first_segment + 1)
    {
      if ((void *)new_srh->segments + sizeof(struct in6_addr) * (i + 1) <= data_end && (void *)old_srh->segments + sizeof(struct in6_addr) * (i + 1) <= data_end)
      {
        struct in6_addr a = old_srh->segments[i];
        new_srh->segments[i] = a;
      }
    }
    else
    {
      break;
    }
  }
  __builtin_memcpy(new_pktid_tlv, &pktid_tlv, sizeof(pktid_tlv));

  // chage length fields
  if (update_pkt_len(new_ipv6, new_srh, sizeof(*new_pktid_tlv)))
  {
    return true;
  }

  return false;
}

static __always_inline bool push_pktidtlv_skb(struct __sk_buff *skb, int tlv_off, int nodeid, int counter)
{
  void *data_end = (void *)(long)skb->data_end;
  void *data = (void *)(long)skb->data;
  // new pktid_tlv
  struct sr6_pktid_tlv pktid_tlv = new_pktid_tlv(nodeid, counter);

  int err;

  // adjust ipv6
  err = bpf_skb_adjust_room(skb, sizeof(pktid_tlv), BPF_ADJ_ROOM_NET, 0);
  if (err != 0)
  {
    bpf_debug("bpf_skb_ajust_room error.");
    return false;
  }

  // new data and data_end
  data_end = (void *)(long)skb->data_end;
  data = (void *)(long)skb->data;
  // new eth
  struct ethhdr *eth = data;
  if ((void *)eth + sizeof(*eth) > data_end)
  {
    return false;
  }
  struct ipv6hdr *ipv6 = (void *)eth + sizeof(*eth);
  if ((void *)ipv6 + sizeof(*ipv6) > data_end)
  {
    return false;
  }

  struct ipv6_sr_hdr *new_srh = (void *)ipv6 + sizeof(*ipv6);
  struct ipv6_sr_hdr *old_srh = (void *)new_srh + sizeof(pktid_tlv);
  struct ipv6_sr_hdr tmp_srh;
  if ((void *)new_srh + sizeof(*new_srh) > data_end || (void *)old_srh + sizeof(*old_srh) > data_end)
  {
    bpf_debug("push_pktidtlv_skb: SRH parcing ERROR.");
    return false;
  }
  __builtin_memcpy(&tmp_srh, old_srh, sizeof(tmp_srh));
  __builtin_memcpy(new_srh, &tmp_srh, sizeof(*new_srh));

  // copy segment list from old srh
  for (int i = 0; i < 15; i++)
  {
    if (i < new_srh->first_segment + 1)
    {
      if ((void *)new_srh->segments + sizeof(struct in6_addr) * (i + 1) <= data_end && (void *)old_srh->segments + sizeof(struct in6_addr) * (i + 1) <= data_end)
      {
        struct in6_addr a = old_srh->segments[i];
        new_srh->segments[i] = a;
      }
    }
    else
    {
      break;
    }
  }

  // set new Pktid TLV
  unsigned long segments_size = (new_srh->first_segment + 1) * sizeof(struct in6_addr);
  struct sr6_pktid_tlv *new_pktid_tlv = (void *)new_srh + sizeof(*new_srh) + segments_size;
  if ((void *)new_pktid_tlv + sizeof(*new_pktid_tlv) > data_end)
  {
    return false;
  }
  __builtin_memcpy(new_pktid_tlv, &pktid_tlv, sizeof(pktid_tlv));

  // unsigned int offset = sizeof(*eth) + sizeof(*ipv6) + sizeof(*new_srh);
  // err = bpf_skb_store_bytes(skb, offset, &pktid_tlv, sizeof(pktid_tlv), 0);
  // if(err != 0){
  //   bpf_debug("bpf_skb_store_bytes: ERROR.");
  //   return false;
  // }

  // chage length fields
  if (update_pkt_len(ipv6, new_srh, sizeof(*new_pktid_tlv)))
  {
    return true;
  }

  return false;
}

/**
 * @brief perf_event
 *
 * @param ctx
 * @param packet_size
 * @param pktid
 * @param hookpoint
 * @return __always_inline
 */
static __always_inline long perf_event(void *ctx, __u64 packet_size, unsigned long long pktid, __u8 hookpoint)
{
  struct perf_event_item evt = {
      .pktid = 0,
      .hookpoint = 0,
  };
  // ensure padding
  __builtin_memset(&evt, 0, sizeof(evt));

  evt.pktid = pktid;
  evt.hookpoint = hookpoint;
  evt.monotonic_timestamp = bpf_ktime_get_ns();

  __u64 flags = BPF_F_CURRENT_CPU | (packet_size << 32);
  return bpf_perf_event_output(ctx, &perf_map, flags, &evt, sizeof(evt));
}

// Ingress Prog
SEC("xdp")
int ingress(struct xdp_md *ctx)
{
  bpf_trace("Ingress: Enter packet");
  void *data_end = (void *)(long)ctx->data_end;
  void *data = (void *)(long)ctx->data;
  __u64 packet_size = data_end - data;

  __u32 counter_index = 0;
  __u32 node_id_index = NODEID_INDEX;

  struct ipv6_sr_hdr *srh = get_srh(data, data_end);
  if (srh == NULL)
  {
    bpf_trace("Ingress: No SRv6 Packet.");
    return XDP_PASS;
  }
  bpf_trace("Ingress: Get SRv6 Packet.");
  // perf_event(ctx, packet_size, 1, 1);

  struct sr6_pktid_tlv *tlv = get_pktidtlv(srh, data, data_end);
  if (tlv)
  {
    bpf_trace("Ingress: PktId TLV Packet");
    // Perf Event

    unsigned long long pktid = (nodeidtoi(tlv->node_id) << (PKTID_TLV_COUNTER_LEN * 8)) + countertoi(tlv->counter, data_end);
    perf_event(ctx, packet_size, pktid, 1);
  }
  else
  {
    // PKTID 付与
    __u32 *node_id = bpf_map_lookup_elem(&config_map, &node_id_index);
    // __u32 node_id = 1;
    if (node_id == NULL)
    {
      bpf_warn("Ingress: Node id is not found in Map.");
      return XDP_PASS;
    }
    __u32 *count = bpf_map_lookup_elem(&counter_map, &counter_index);
    // __u32 count = 1;
    if (count == NULL)
    {
      bpf_warn("Ingress: Counter is not found in Map.");
      return XDP_PASS;
    }

    if (push_pktidtlv_xdp(ctx, *node_id, *count))
    {
      (*count)++;
      // Perf Event
      unsigned long long pktid = ((unsigned long long)*node_id << (PKTID_TLV_COUNTER_LEN * 8)) | (unsigned long long)*count;
      perf_event(ctx, packet_size, pktid, 2);
    }
    else
    {
      bpf_warn("Ingress: Adding PktId TLV Error.");
      return XDP_PASS;
    }

    bpf_debug("Ingress: PktId TLV added to SRH.");
  }

  return XDP_PASS;
}

// Egress Prog
SEC("tc")
int egress(struct __sk_buff *skb)
{
  bpf_trace("Engress: Enter packet");
  void *data_end = (void *)(long)skb->data_end;
  void *data = (void *)(long)skb->data;
  __u64 packet_size = data_end - data;

  __u32 counter_index = COUNTER_INDEX;
  __u32 node_id_index = NODEID_INDEX;

  struct ipv6_sr_hdr *srh = get_srh(data, data_end);
  if (srh == NULL)
  {
    bpf_trace("Egress: No SRv6 Packet.");
    return TC_ACT_OK;
  }
  bpf_trace("Egress: Get SRv6 Packet.");

  struct sr6_pktid_tlv *tlv = get_pktidtlv(srh, data, data_end);
  if (tlv)
  {
    bpf_trace("Egress: PktId TLV Packet.");
  }
  else
  {
    // PKTID 付与
    __u32 *node_id = bpf_map_lookup_elem(&config_map, &node_id_index);
    if (node_id == NULL)
    {
      bpf_warn("Egress: Node id is not found in Map.");
      return TC_ACT_OK;
    }

    __u32 *counter = bpf_map_lookup_elem(&config_map, &node_id_index);
    if (counter == NULL)
    {
      bpf_warn("Egress: Counter is not found in Map.");
      return TC_ACT_OK;
    }

    int tlv_off = (void *)(srh + sizeof(*srh)) - data;
    if (push_pktidtlv_skb(skb, tlv_off, *node_id, *counter))
    {
      (*counter)++;
      // Perf Event
      unsigned long long pktid = ((unsigned long long)*node_id << (PKTID_TLV_COUNTER_LEN * 8)) | (unsigned long long)*counter;
      perf_event(skb, packet_size, pktid, 4);
    }
    else
    {
      bpf_warn("Egress: Adding PktId TLV Error.");
      return TC_ACT_OK;
    }

    bpf_debug("Egress: PktId TLV added to SRH.");
  }

  return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";
