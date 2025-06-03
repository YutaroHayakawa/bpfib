/*
Copyright © 2024 Yutaro Hayakawa

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

	http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
package cmd

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"math"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"syscall"
	"text/tabwriter"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/spf13/cobra"
)

type lookupIn struct {
	Family       int
	L4Proto      int
	SPort        uint16
	DPort        uint16
	TotLen       uint16
	Ifindex      uint32
	IPv4ToS      *uint8
	IPv6FlowInfo *uint32
	SrcAddr      netip.Addr
	DstAddr      netip.Addr
	TableID      *uint32
	Mark         *uint32
}

func (in *lookupIn) marshal() []byte {
	buf := &bytes.Buffer{}
	// param->family
	buf.WriteByte(byte(in.Family))
	// param->l4proto
	buf.WriteByte(byte(in.L4Proto))
	// param->sport
	binary.Write(buf, binary.BigEndian, in.SPort)
	// param->dport
	binary.Write(buf, binary.BigEndian, in.DPort)
	// param->tot_len
	binary.Write(buf, binary.NativeEndian, in.TotLen)
	// param->ifindex
	binary.Write(buf, binary.NativeEndian, in.Ifindex)
	// param->ipv4_tos or param->ipv6_flowinfo
	if in.IPv4ToS != nil {
		binary.Write(buf, binary.NativeEndian, in.IPv4ToS)
		binary.Write(buf, binary.NativeEndian, uint8(0))
		binary.Write(buf, binary.NativeEndian, uint8(0))
		binary.Write(buf, binary.NativeEndian, uint8(0))
	} else if in.IPv6FlowInfo != nil {
		binary.Write(buf, binary.BigEndian, in.IPv6FlowInfo)
	} else {
		binary.Write(buf, binary.NativeEndian, uint32(0))
	}
	// param->ipv4_src or param->ipv6_src
	if in.SrcAddr.Is4() {
		a := in.SrcAddr.As4()
		buf.Write(a[:])
		binary.Write(buf, binary.BigEndian, uint32(0))
		binary.Write(buf, binary.BigEndian, uint32(0))
		binary.Write(buf, binary.BigEndian, uint32(0))
	} else {
		a := in.SrcAddr.As16()
		buf.Write(a[:])
	}
	// param->ipv4_dst or param->ipv6_dst
	if in.DstAddr.Is4() {
		a := in.DstAddr.As4()
		buf.Write(a[:])
		binary.Write(buf, binary.BigEndian, uint32(0))
		binary.Write(buf, binary.BigEndian, uint32(0))
		binary.Write(buf, binary.BigEndian, uint32(0))
	} else {
		a := in.DstAddr.As16()
		buf.Write(a[:])
	}
	// param->tbid
	if in.TableID != nil {
		binary.Write(buf, binary.NativeEndian, in.TableID)
	} else {
		binary.Write(buf, binary.NativeEndian, uint32(0))
	}
	// param->mark
	if in.Mark != nil {
		binary.Write(buf, binary.NativeEndian, in.Mark)
	} else {
		binary.Write(buf, binary.NativeEndian, uint32(0))
	}
	// Padding
	buf.Write(bytes.Repeat([]byte{0}, 8))
	return buf.Bytes()
}

type lookupOut struct {
	Family    string
	MTU       uint16
	Iface     string
	Metric    uint32
	Source    netip.Addr
	NextHop   netip.Addr
	VlanProto uint16
	VlanTCI   uint16
	SMAC      [6]byte
	DMAC      [6]byte
}

func (out *lookupOut) String(queryAddr netip.Addr) string {
	var s string
	s += fmt.Sprintf("%s ", queryAddr.String())
	if out.NextHop != queryAddr && !out.NextHop.IsUnspecified() {
		s += fmt.Sprintf("via %s ", out.NextHop)
	}
	if out.Iface != "" {
		s += fmt.Sprintf("dev %s ", out.Iface)
	}
	if out.MTU != 0 {
		s += fmt.Sprintf("mtu %d ", out.MTU)
	}
	if out.VlanProto != 0 {
		s += fmt.Sprintf("vlan-proto %d ", out.VlanProto)
	}
	if out.VlanTCI != 0 {
		s += fmt.Sprintf("vlan-tci %d ", out.VlanTCI)
	}
	if out.SMAC != [6]byte{} {
		s += fmt.Sprintf("smac %s ", net.HardwareAddr(out.SMAC[:]).String())
	}
	if out.DMAC != [6]byte{} {
		s += fmt.Sprintf("dmac %s ", net.HardwareAddr(out.DMAC[:]).String())
	}
	if out.Metric != 0 {
		s += fmt.Sprintf("metric %d ", out.Metric)
	}
	if !out.Source.IsUnspecified() {
		s += fmt.Sprintf("src %s ", out.Source)
	}
	return s
}

func (out *lookupOut) unmarshal(data []byte) {
	var (
		b uint8
		w uint32
	)

	buf := bytes.NewReader(data)

	// param->family
	binary.Read(buf, binary.NativeEndian, &b)
	switch b {
	case syscall.AF_INET:
		out.Family = "inet"
	case syscall.AF_INET6:
		out.Family = "inet6"
	default:
		out.Family = fmt.Sprintf("unknown(%d)", b)
	}

	// skip l4_protocol, sport, dport
	binary.Read(buf, binary.NativeEndian, &[5]byte{})

	// param->mtu_result
	binary.Read(buf, binary.NativeEndian, &out.MTU)

	// param->ifindex, resolve to iface name
	binary.Read(buf, binary.NativeEndian, &w)
	iface, err := net.InterfaceByIndex(int(w))
	if err != nil {
		out.Iface = fmt.Sprintf("unknown(%d)", w)
	} else {
		out.Iface = iface.Name
	}

	// param->rt_metric
	binary.Read(buf, binary.NativeEndian, &out.Metric)

	// param->ipv4_src or ipv6_src
	switch out.Family {
	case "inet":
		var (
			addr [4]byte
			pad  [12]byte
		)
		binary.Read(buf, binary.BigEndian, &addr)
		out.Source = netip.AddrFrom4(addr)
		binary.Read(buf, binary.BigEndian, &pad)
	case "inet6":
		var addr [16]byte
		binary.Read(buf, binary.BigEndian, &addr)
		out.Source = netip.AddrFrom16(addr)
	default:
		out.Source = netip.Addr{}
	}
	binary.Read(buf, binary.NativeEndian, &[16]byte{})

	// param->ipv4_dst or param->ipv6_dst
	switch out.Family {
	case "inet":
		var (
			addr [4]byte
			pad  [12]byte
		)
		binary.Read(buf, binary.BigEndian, &addr)
		out.NextHop = netip.AddrFrom4(addr)
		binary.Read(buf, binary.BigEndian, &pad)
	case "inet6":
		var addr [16]byte
		binary.Read(buf, binary.BigEndian, &addr)
		out.NextHop = netip.AddrFrom16(addr)
	default:
		out.NextHop = netip.Addr{}
	}

	// param->h_vlan_proto
	binary.Read(buf, binary.BigEndian, &out.VlanProto)

	// param->h_vlan_tci
	binary.Read(buf, binary.BigEndian, &out.VlanTCI)

	// param->smac, param->dmac
	binary.Read(buf, binary.NativeEndian, &out.SMAC)
	binary.Read(buf, binary.NativeEndian, &out.DMAC)
}

// lookupCmd represents the lookup command
var lookupCmd = &cobra.Command{
	Use:   "lookup [flags] dest iif [options]",
	Short: "Lookup FIB using bpf_fib_lookup helper function",
	Long:  "Lookup FIB using bpf_fib_lookup helper function",
	Run: func(cmd *cobra.Command, args []string) {
		in := &lookupIn{}

		if len(args) < 2 {
			cmd.PrintErrf("Argument too short\n\n")
			cmd.Help()
			return
		}

		// The first option must be destination address
		dst, err := netip.ParseAddr(args[0])
		if err != nil {
			cmd.PrintErrf("Failed to parse destination: %s\n\n", err)
			cmd.Help()
			return
		}

		if dst.Is4() {
			in.Family = syscall.AF_INET
		} else {
			in.Family = syscall.AF_INET6
		}

		in.DstAddr = dst

		// The second option must be input interface
		iif, err := net.InterfaceByName(args[1])
		if err != nil {
			cmd.PrintErrf("Failed to get input interface: %s\n\n", err)
			cmd.Help()
			return
		}

		in.Ifindex = uint32(iif.Index)

		// Rest of the arguments are optional
		if err = parseLookupArgs(in, args[2:]); err != nil {
			cmd.PrintErrf("Failed to parse args: %s\n\n", err)
			cmd.Help()
			return
		}

		// Additional flags for bpf_fib_lookup
		flags := uint32(0)
		if direct, _ := cmd.Flags().GetBool("direct"); direct {
			flags |= BFP_FIB_LOOKUP_DIRECT
		}
		if output, _ := cmd.Flags().GetBool("output"); output {
			flags |= BFP_FIB_LOOKUP_OUTPUT
		}
		if skipNeigh, _ := cmd.Flags().GetBool("skip-neigh"); skipNeigh {
			flags |= BPF_FIB_LOOKUP_SKIP_NEIGH
		}
		if in.TableID != nil {
			if flags&BFP_FIB_LOOKUP_DIRECT == 0 {
				cmd.PrintErrf("Forcefully setting BFP_FIB_LOOKUP_DIRECT option since you specified table option which requires direct lookup. To suppress this message, set --direct flag explicitly.\n")
				flags |= BFP_FIB_LOOKUP_DIRECT
			}
			flags |= BFP_FIB_LOOKUP_TBID
		}
		if src, _ := cmd.Flags().GetBool("src"); src {
			flags |= BFP_FIB_LOOKUP_SRC
		}
		if in.Mark != nil {
			if flags&BPF_FIB_LOOKUP_DIRECT != 0 {
				cmd.PrintErrf("Forcefully resetting BFP_FIB_LOOKUP_DIRECT option since you specified mark option which should not be used with direct lookup. To suppress this message, don't set --direct flag.\n")
				flags &^= BFP_FIB_LOOKUP_DIRECT
			}
		}

		// Serialize input parameters to write struct bpf_fib_lookup to map
		param := in.marshal()
		paramSize := uint32(len(param))

		// Create eBPF program and load it
		colSpec := ebpf.CollectionSpec{
			Maps: map[string]*ebpf.MapSpec{
				"param": {
					Name:       "param",
					Type:       ebpf.Array,
					KeySize:    uint32(unsafe.Sizeof(uint32(0))),
					ValueSize:  paramSize,
					MaxEntries: 1,
					Contents: []ebpf.MapKV{
						{
							Key:   uint32(0),
							Value: param,
						},
					},
				},
			},
			Programs: map[string]*ebpf.ProgramSpec{
				"lookup": {
					Name:    "lookup",
					Type:    ebpf.SchedCLS,
					License: "GPL",
					Instructions: asm.Instructions{
						// Save context
						asm.Mov.Reg(asm.R6, asm.R1),
						// Prepare for bpf_map_lookup_elem
						asm.StoreImm(asm.R10, -4, 0, asm.Word),
						// Get parameter from map
						asm.LoadMapPtr(asm.R1, 0).WithReference("param"),
						asm.Mov.Reg(asm.R2, asm.R10),
						asm.Add.Imm(asm.R2, -4),
						asm.FnMapLookupElem.Call(),
						// NULL check
						asm.Instruction{OpCode: asm.JNE.Op(asm.ImmSource), Constant: 0, Offset: 3},
						asm.LoadImm(asm.R0, math.MinInt32, asm.DWord),
						asm.Return(),
						// Call bpf_fib_lookup
						asm.Mov.Reg(asm.R1, asm.R6),
						asm.Mov.Reg(asm.R2, asm.R0),
						asm.LoadImm(asm.R3, int64(paramSize), asm.DWord),
						asm.LoadImm(asm.R4, int64(flags), asm.DWord),
						asm.FnFibLookup.Call(),
						// Return
						asm.Return(),
					},
				},
			},
		}

		col, err := ebpf.NewCollection(&colSpec)
		if err != nil {
			cmd.PrintErrf("Failed to create collection: %s\n\n", err)
			return
		}

		// We don't need to attach the program to any interface. Just
		// run it should be sufficient to test the bpf_fib_lookup.
		uret, _, err := col.Programs["lookup"].Test(bytes.Repeat([]byte{0xff}, 64))
		if err != nil {
			cmd.PrintErrf("Failed to run program: %s\n\n", err)
			return
		}

		ret := int32(uret)

		data := make([]byte, paramSize)

		// The kernel should have written the result to the map. Extract it.
		if err := col.Maps["param"].Lookup(uint32(0), data); err != nil {
			cmd.PrintErrf("Failed to lookup result: %s\n\n", err)
			return
		}

		out := &lookupOut{}
		out.unmarshal(data)

		switch ret {
		case BPF_FIB_LKUP_RET_SUCCESS:
			// Print lookup result on success
			cmd.Println(out.String(dst))
		case BPF_FIB_LKUP_RET_BLACKHOLE:
			cmd.Println("Blackhole (BPF_FIB_LKUP_RET_BLACKHOLE)")
		case BPF_FIB_LKUP_RET_UNREACHABLE:
			cmd.Println("Unreachable (BPF_FIB_LKUP_RET_UNREACHABLE)")
		case BPF_FIB_LKUP_RET_PROHIBIT:
			cmd.Println("Prohibit (BPF_FIB_LKUP_RET_PROHIBIT)")
		case BPF_FIB_LKUP_RET_NOT_FWDED:
			cmd.Println("Not Forwarded (BPF_FIB_LKUP_RET_NOT_FWDED)")
		case BPF_FIB_LKUP_RET_FWD_DISABLED:
			cmd.Println("Forward Disabled (BPF_FIB_LKUP_RET_FWD_DISABLED)")
		case BPF_FIB_LKUP_RET_UNSUPP_LWT:
			cmd.Println("LWT Not Supported (BPF_FIB_LKUP_RET_UNSUPP_LWT)")
		case BPF_FIB_LKUP_RET_NO_NEIGH:
			// Neighbor resolution needed, but the FIB lookup was successful.
			// The output should contain the partial result.
			cmd.Println("No Neighbor (BPF_FIB_LKUP_RET_NO_NEIGH)")
			cmd.Println(out.String(dst))
		case BPF_FIB_LKUP_RET_FRAG_NEEDED:
			// From bpf-helpers(7):
			// If lookup fails with BPF_FIB_LKUP_RET_FRAG_NEEDED,
			// then the MTU was exceeded and output
			// params->mtu_result contains the MTU.
			cmd.Printf("Fragmentation Needed (BPF_FIB_LKUP_RET_FRAG_NEEDED) mtu %d\n", out.MTU)
		case BPF_FIB_LKUP_RET_NO_SRC_ADDR:
			// No source address found, but the FIB lookup was successful.
			// The output should contain the partial result.
			cmd.Println("No Source Address (BPF_FIB_LKUP_RET_NO_SRC_ADDR)")
			cmd.Println(out.String(dst))
		case math.MinInt32:
			cmd.Println("BUG: bpf_fib_lookup failed")
		default:
			if ret < 0 {
				ret = -ret
			}
			cmd.Println(syscall.Errno(ret).Error())
		}
	},
}

type lookupOpt struct {
	desc   []string
	handle func(*lookupIn, []string) (int, error)
	probe  func() bool
}

var lookupCmdOpts = map[string]lookupOpt{
	"l4proto": {
		desc: []string{"l4proto", "<tcp|udp>", "L4 protocol"},
		handle: func(in *lookupIn, args []string) (int, error) {
			if len(args) == 0 {
				return 0, fmt.Errorf("l4proto is unspecified")
			}
			if err := parseL4Proto(in, args[0]); err != nil {
				return 0, err
			}
			return 1, nil
		},
		probe: func() bool { return true },
	},
	"sport": {
		desc: []string{"sport", "<port>", "Source port"},
		handle: func(in *lookupIn, args []string) (int, error) {
			if len(args) == 0 {
				return 0, fmt.Errorf("sport is unspecified")
			}
			if err := parsePort(&in.SPort, args[0]); err != nil {
				return 0, err
			}
			return 1, nil
		},
		probe: func() bool { return true },
	},
	"dport": {
		desc: []string{"dport", "<port>", "Destination port"},
		handle: func(in *lookupIn, args []string) (int, error) {
			if len(args) == 0 {
				return 0, fmt.Errorf("dport is unspecified")
			}
			if err := parsePort(&in.DPort, args[0]); err != nil {
				return 0, err
			}
			return 1, nil
		},
		probe: func() bool { return true },
	},
	"totlen": {
		desc: []string{"totlen", "<length>", "Total length of the IP packet"},
		handle: func(in *lookupIn, args []string) (int, error) {
			if len(args) == 0 {
				return 0, fmt.Errorf("totlen is unspecified")
			}
			totlen, err := strconv.ParseUint(args[0], 10, 16)
			if err != nil {
				return 0, fmt.Errorf("cannot parse totlen: %w", err)
			}
			in.TotLen = uint16(totlen)
			return 1, nil
		},
		probe: func() bool { return true },
	},
	"tos": {
		desc: []string{"tos", "<tos in hex>", "ToS for IPv4"},
		handle: func(in *lookupIn, args []string) (int, error) {
			if len(args) == 0 {
				return 0, fmt.Errorf("tos is unspecified")
			}
			tos64, err := strconv.ParseUint(args[0], 16, 8)
			if err != nil {
				return 0, fmt.Errorf("cannot parse tos: %w", err)
			}
			tos8 := uint8(tos64)
			in.IPv4ToS = &tos8
			return 1, nil
		},
		probe: func() bool { return true },
	},
	"flowinfo": {
		desc: []string{"flowinfo", "<flowinfo in hex>", "Flow Label + Priority for IPv6"},
		handle: func(in *lookupIn, args []string) (int, error) {
			if len(args) == 0 {
				return 0, fmt.Errorf("flowinfo is unspecified")
			}
			flowinfo64, err := strconv.ParseUint(args[0], 16, 32)
			if err != nil {
				return 0, fmt.Errorf("cannot parse flowinfo: %w", err)
			}
			flowinfo32 := uint32(flowinfo64)
			in.IPv6FlowInfo = &flowinfo32
			return 1, nil
		},
		probe: func() bool { return true },
	},
	"from": {
		desc: []string{"from", "<address>", "Source address"},
		handle: func(in *lookupIn, args []string) (int, error) {
			if len(args) == 0 {
				return 0, fmt.Errorf("src is unspecified")
			}
			addr, err := netip.ParseAddr(args[0])
			if err != nil {
				return 0, fmt.Errorf("cannot parse src: %w", err)
			}
			in.SrcAddr = addr
			return 1, nil
		},
		probe: func() bool { return true },
	},
	"table": {
		desc: []string{"table", "<table id>", "Table ID"},
		handle: func(in *lookupIn, args []string) (int, error) {
			if len(args) == 0 {
				return 0, fmt.Errorf("table is unspecified")
			}
			tableID, err := strconv.ParseUint(args[0], 10, 32)
			if err != nil {
				return 0, fmt.Errorf("cannot parse table id: %w", err)
			}
			tableID32 := uint32(tableID)
			in.TableID = &tableID32
			return 1, nil
		},
		probe: func() bool { return true },
	},
	"mark": {
		desc: []string{"mark", "<mark>", "Mark"},
		handle: func(in *lookupIn, args []string) (int, error) {
			if len(args) == 0 {
				return 0, fmt.Errorf("mark is unspecified")
			}
			mark, err := strconv.ParseUint(args[0], 0, 32)
			if err != nil {
				return 0, fmt.Errorf("cannot parse mark: %w", err)
			}
			mark32 := uint32(mark)
			in.Mark = &mark32
			return 1, nil
		},
		probe: func() bool { return false },
	},
}

func parseLookupArgs(in *lookupIn, args []string) error {
	if len(args) == 0 {
		return nil
	}
	opt, found := lookupCmdOpts[args[0]]
	if !found {
		return fmt.Errorf("unknown option: %s", args[0])
	}
	consumed, err := opt.handle(in, args[1:])
	if err != nil {
		return err
	}
	return parseLookupArgs(in, args[1+consumed:])
}

func parseL4Proto(in *lookupIn, arg string) error {
	switch arg {
	case "tcp":
		in.L4Proto = syscall.IPPROTO_TCP
	case "udp":
		in.L4Proto = syscall.IPPROTO_UDP
	default:
		return fmt.Errorf("unknown l4proto: %s", arg)
	}
	return nil
}

func parsePort(in *uint16, arg string) error {
	port, err := strconv.ParseUint(arg, 10, 16)
	if err != nil {
		return fmt.Errorf("cannot parse port: %w", err)
	}
	*in = uint16(port)
	return nil
}

func lookupOptsMultiLine() string {
	b := &strings.Builder{}
	w := new(tabwriter.Writer)
	w.Init(b, 0, 8, 8, '\t', 0)
	for _, opt := range lookupCmdOpts {
		fmt.Fprintf(w, "\t%s\t%s\t%s\n", opt.desc[0], opt.desc[1], opt.desc[2])
	}
	w.Flush()
	return b.String()
}

func lookupUsage(cmd *cobra.Command) error {
	cmd.PrintErrf("Usage: %s\n\n", cmd.Use)
	cmd.PrintErrf("Options:\n\n%s\n", lookupOptsMultiLine())
	cmd.PrintErrf("Flags:\n%s\n", cmd.LocalFlags().FlagUsages())
	return nil
}

func init() {
	rootCmd.AddCommand(lookupCmd)
	lookupCmd.SetUsageFunc(lookupUsage)
	lookupCmd.Flags().Bool("direct", false, "Set direct option (BPF_FIB_LOOKUP_DIRECT)")
	lookupCmd.Flags().Bool("output", false, "Set output option (BPF_FIB_LOOKUP_OUTPUT)")
	lookupCmd.Flags().Bool("skip-neigh", false, "Set skip-neigh option (BPF_FIB_LOOKUP_SKIP_NEIGH)")
	lookupCmd.Flags().Bool("src", false, "Set src option (BPF_FIB_LOOKUP_SRC)")
}
