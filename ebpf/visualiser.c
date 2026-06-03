// go:build ignore
#include "vmlinux.h"
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

// Every eBPF program must declare a GPL-compatible license
// to unlock the kernel's advanced helper functions.
char __license[] SEC("license") = "GPL";

// 1. The structural blueprint of the data we want to collect.
// This exact layout will be read by our Go application.
struct connection_event {
  u32 src_ip;
  u32 dst_ip;
  u16 src_port;
  u16 dst_port;
  u8 comm[16]; // Stores the 16-character process name (e.g., "curl", "nginx")
};

// 2. Define the lockless shared memory conveyor belt (Ring Buffer Map).
struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, 1 << 16); // Allocation size: 64KB
} conn_events SEC(".maps");

// 3. The Camera Hook: Tell the kernel to run this code
// the exact microsecond any process enters 'tcp_connect'.
SEC("fentry/tcp_connect")
int BPF_PROG(tcp_connect, struct sock *sk) {

  // Extract the socket's address family (IPv4 vs IPv6).
  // skc_family lives deep inside the kernel's socket tracking structures.
  u16 family = 0;
  if (bpf_probe_read_kernel(&family, sizeof(family),
                            &sk->__sk_common.skc_family) < 0) {
    return 0;
  }

  // Filter: If it's not an IPv4 connection (AF_INET is 2), ignore it.
  // This keeps our personal project simple and clean.
  if (family != 2) {
    return 0;
  }

  // Safely reserve a slot on our Ring Buffer memory conveyor belt.
  struct connection_event *ev;
  ev = bpf_ringbuf_reserve(&conn_events, sizeof(*ev), 0);
  if (!ev) {
    return 0; // Buffer is full; drop this telemetry event to protect kernel
              // performance
  }

  // Read the binary IP data directly from the kernel socket pointers
  if (bpf_probe_read_kernel(&ev->src_ip, sizeof(ev->src_ip),
                            &sk->__sk_common.skc_rcv_saddr) < 0) {
    bpf_ringbuf_discard(ev, 0);
    return 0;
  }
  if (bpf_probe_read_kernel(&ev->dst_ip, sizeof(ev->dst_ip),
                            &sk->__sk_common.skc_daddr) < 0) {
    bpf_ringbuf_discard(ev, 0);
    return 0;
  }

  // Read the ports. The kernel stores the destination port in network byte
  // order (Big Endian). We convert it to host byte order (Little Endian on
  // standard x86/ARM hardware) using bpf_ntohs.
  u16 dport = 0;
  if (bpf_probe_read_kernel(&dport, sizeof(dport),
                            &sk->__sk_common.skc_dport) < 0) {
    bpf_ringbuf_discard(ev, 0);
    return 0;
  }
  ev->dst_port = bpf_ntohs(dport);

  if (bpf_probe_read_kernel(&ev->src_port, sizeof(ev->src_port),
                            &sk->__sk_common.skc_num) < 0) {
    bpf_ringbuf_discard(ev, 0);
    return 0;
  }

  // Ask the kernel context to copy the name of the executable
  // occupying the CPU into our event structure.
  if (bpf_get_current_comm(&ev->comm, sizeof(ev->comm)) < 0) {
    bpf_ringbuf_discard(ev, 0);
    return 0;
  }

  // Submit the data slot. This instantly notifies our user-space Go program.
  bpf_ringbuf_submit(ev, 0);

  return 0;
}
