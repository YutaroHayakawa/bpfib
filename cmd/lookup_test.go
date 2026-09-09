package cmd

import (
	"bytes"
	"testing"

	"github.com/spf13/cobra"
)

func newLookupFlagCommand(t *testing.T) *cobra.Command {
	t.Helper()

	cmd := &cobra.Command{}
	cmd.SetErr(new(bytes.Buffer))
	cmd.Flags().Bool("direct", false, "")
	cmd.Flags().Bool("output", false, "")
	cmd.Flags().Bool("skip-neigh", false, "")
	cmd.Flags().Bool("src", false, "")

	return cmd
}

func TestBuildLookupFlagsMarkSetsMarkAndClearsDirect(t *testing.T) {
	t.Parallel()

	cmd := newLookupFlagCommand(t)
	if err := cmd.Flags().Set("direct", "true"); err != nil {
		t.Fatalf("set direct: %v", err)
	}

	mark := uint32(0x42)
	flags := buildLookupFlags(cmd, &lookupIn{Mark: &mark})

	if flags&BPF_FIB_LOOKUP_MARK == 0 {
		t.Fatalf("expected mark flag to be set, got %#x", flags)
	}
	if flags&BPF_FIB_LOOKUP_DIRECT != 0 {
		t.Fatalf("expected direct flag to be cleared, got %#x", flags)
	}
}

func TestBuildLookupFlagsTableSetsDirectAndTBID(t *testing.T) {
	t.Parallel()

	cmd := newLookupFlagCommand(t)
	tableID := uint32(100)

	flags := buildLookupFlags(cmd, &lookupIn{TableID: &tableID})

	if flags&BPF_FIB_LOOKUP_DIRECT == 0 {
		t.Fatalf("expected direct flag to be set, got %#x", flags)
	}
	if flags&BPF_FIB_LOOKUP_TBID == 0 {
		t.Fatalf("expected tbid flag to be set, got %#x", flags)
	}
}

func TestBuildLookupFlagsCombinesIndependentFlags(t *testing.T) {
	t.Parallel()

	cmd := newLookupFlagCommand(t)
	for _, name := range []string{"output", "skip-neigh", "src"} {
		if err := cmd.Flags().Set(name, "true"); err != nil {
			t.Fatalf("set %s: %v", name, err)
		}
	}

	flags := buildLookupFlags(cmd, &lookupIn{})

	want := BPF_FIB_LOOKUP_OUTPUT | BPF_FIB_LOOKUP_SKIP_NEIGH | BPF_FIB_LOOKUP_SRC
	if flags != want {
		t.Fatalf("unexpected flags: got %#x want %#x", flags, want)
	}
}
