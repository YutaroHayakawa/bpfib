package cmd

const (
	BPF_FIB_LOOKUP_DIRECT     = uint32(1) << 0
	BPF_FIB_LOOKUP_OUTPUT     = uint32(1) << 1
	BPF_FIB_LOOKUP_SKIP_NEIGH = uint32(1) << 2
	BPF_FIB_LOOKUP_TBID       = uint32(1) << 3
	BPF_FIB_LOOKUP_SRC        = uint32(1) << 4
	BPF_FIB_LOOKUP_MARK       = uint32(1) << 5
)

const (
	BPF_FIB_LKUP_RET_SUCCESS = iota
	BPF_FIB_LKUP_RET_BLACKHOLE
	BPF_FIB_LKUP_RET_UNREACHABLE
	BPF_FIB_LKUP_RET_PROHIBIT
	BPF_FIB_LKUP_RET_NOT_FWDED
	BPF_FIB_LKUP_RET_FWD_DISABLED
	BPF_FIB_LKUP_RET_UNSUPP_LWT
	BPF_FIB_LKUP_RET_NO_NEIGH
	BPF_FIB_LKUP_RET_FRAG_NEEDED
	BPF_FIB_LKUP_RET_NO_SRC_ADDR
)
