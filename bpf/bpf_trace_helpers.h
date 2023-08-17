#include "bpf_helpers.h"
#include <endian.h>

#define HOOK_XDP_INGRESS_GET 1
#define HOOK_XDP_INGRESS_PUSH 2
#define HOOK_TC_EGRESS_GET 3
#define HOOK_TC_EGRESS_PUSH 4
#define HOOK_LWT_IN_GET 5
#define HOOK_LWT_IN_PUSH 6
#define HOOK_LWT_XMIT_GET 7
#define HOOK_LWT_XMIT_PUSH 8
#define HOOK_LWT_OUT_GET 9
#define HOOK_LWT_OUT_PUSH 10
#define HOOK_LWT_SEG6LOCAL_GET 11
#define HOOK_LWT_SEG6LOCAL_PUSH 12

#define WARNING
#ifdef WARNING
#define bpf_warn(fmt, args...) bpf_printk(fmt, ##args)
#else
#define bpf_warn(fmt, args...)
#endif

// #define INFO
#ifdef INFO
#define bpf_info(fmt, args...) bpf_printk(fmt, ##args)
#else
#define bpf_info(fmt, args...)
#endif

// #define DEBUG
#ifdef DEBUG
#define bpf_debug(fmt, args...) bpf_printk(fmt, ##args)
#else
#define bpf_debug(fmt, args...)
#endif

// #define TRACE
#ifdef TRACE
#define bpf_trace(fmt, args...) bpf_printk(fmt, ##args)
#else
#define bpf_trace(fmt, args...)
#endif