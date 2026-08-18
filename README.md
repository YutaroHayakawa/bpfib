# bpfib

`bpfib` is a CLI tool that contains various subcommands useful for IP routing with BPF.

## Subcommands

### lookup

`bpfib lookup` is an `ip route get`, but for `bpf_fib_lookup`. In some cases,
regular Linux FIB lookup and `bpf_fib_lookup` produces different results for
the same parameter. For example, `bpf_fib_lookup` is forwarding only (cannot
handle the `local` routes), and unicast only (cannot handle multicast routes,
Light Weight Tunnel routes such as MPLS or SRv6 routes). This means `ip route
get` does not always reflect the result of FIB lookup with `bpf_fib_lookup`.
This command allows you to lookup FIB from BPF's perspective, but without
writing BPF program.

#### Usage

```
Lookup FIB using bpf_fib_lookup helper function

Usage: lookup [flags] dest iif [options]

Options:

	dport		<port>				Destination port
	totlen		<length>			Total length of the IP packet
	table		<table id>			Table ID
	mark		<mark>				Mark
	skblen		<skblen>			skb->len
	sport		<port>				Source port
	tos		<tos in hex>			ToS for IPv4
	flowinfo	<flowinfo in hex>		Flow Label + Priority for IPv6
	from		<address>			Source address
	gso_size	<gso_size>			skb_shinfo(skb)->gso_size
	l4proto		<tcp|udp>			L4 protocol

Flags:
      --direct       Set direct option (BPF_FIB_LOOKUP_DIRECT)
  -h, --help         help for lookup
      --output       Set output option (BPF_FIB_LOOKUP_OUTPUT)
      --skip-neigh   Set skip-neigh option (BPF_FIB_LOOKUP_SKIP_NEIGH)
      --src          Set src option (BPF_FIB_LOOKUP_SRC)
```

#### Example

```
$ ip r show dev eth0 table all
default via 10.1.33.1 proto dhcp metric 600
...
local 10.1.33.24 table local proto kernel scope host src 10.1.33.24

$ ip -d r get 10.1.33.1 dev eth0
unicast 10.1.33.1 dev eth0 table main src 10.1.33.24 uid 1000
    cache

$ bpfib lookup 10.1.33.1 eth0
10.1.33.1 dev eth0 mtu 1500 smac f0:9e:4a:8c:0d:34 dmac e4:83:26:4b:ad:bd metric 600

$ ip -d r get 10.1.33.24 dev eth0
local 10.1.33.24 dev lo table local src 10.1.33.24 uid 1000
    cache <local>

$ bpfib lookup 10.1.33.24 eth0
Not Forwarded (BPF_FIB_LKUP_RET_NOT_FWDED)
```
