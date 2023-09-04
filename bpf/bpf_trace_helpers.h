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

#define ENABLE_HOOK_XDP_INGRESS_GET true
#define ENABLE_HOOK_XDP_INGRESS_PUSH true
#define ENABLE_HOOK_TC_EGRESS_GET false
#define ENABLE_HOOK_TC_EGRESS_PUSH true
#define ENABLE_HOOK_LWT_IN_GET false
#define ENABLE_HOOK_LWT_IN_PUSH true
#define ENABLE_HOOK_LWT_XMIT_GET true
#define ENABLE_HOOK_LWT_XMIT_PUSH true
#define ENABLE_HOOK_LWT_OUT_GET false
#define ENABLE_HOOK_LWT_OUT_PUSH true
#define ENABLE_HOOK_LWT_SEG6LOCAL_GET false
#define ENABLE_HOOK_LWT_SEG6LOCAL_PUSH true

#define WARNING
// #define INFO
// #define DEBUG
// #define TRACE

#ifdef WARNING || INFO || DEBUG || TRACE
#define bpf_warn(fmt, args...) bpf_printk(fmt, ##args)
#else
#define bpf_warn(fmt, args...)
#endif

#ifdef INFO || DEBUG || TRACE
#define bpf_info(fmt, args...) bpf_printk(fmt, ##args)
#else
#define bpf_info(fmt, args...)
#endif

#ifdef DEBUG || TRACE
#define bpf_debug(fmt, args...) bpf_printk(fmt, ##args)
#else
#define bpf_debug(fmt, args...)
#endif

#ifdef TRACE
#define bpf_trace(fmt, args...) bpf_printk(fmt, ##args)
#else
#define bpf_trace(fmt, args...)
#endif