package cmd

import (
	"fmt"
	"sync"

	"github.com/cilium/ebpf/btf"
)

var (
	skBuffMembers map[string][2]uint32
	parseOnce     sync.Once
)

func parseSkbBuffMembers() error {
	btfSpec, err := btf.LoadKernelSpec()
	if err != nil {
		return fmt.Errorf("failed to load kernel BTF: %w", err)
	}

	iter := btfSpec.Iterate()
	for iter.Next() {

		if strct, ok := iter.Type.(*btf.Struct); ok && strct.Name == "__sk_buff" {
			fields := make(map[string][2]uint32)

			for _, member := range strct.Members {
				offsetInBytes := member.Offset.Bytes()
				SizeInBytes, err := btf.Sizeof(member.Type)
				if err != nil {
					return fmt.Errorf("failed to get size of member '%s': %w", member.Name, err)
				}
				fields[member.Name] = [2]uint32{uint32(offsetInBytes), uint32(SizeInBytes)}
			}

			skBuffMembers = fields
			return nil
		}
	}

	return fmt.Errorf("__sk_buff struct not found in kernel BTF")
}

func MemberOfSkBuff(field string) (offset, size uint32, err error) {
	parseOnce.Do(func() {
		err = parseSkbBuffMembers()
	})

	if err != nil {
		return 0, 0, err
	}

	member, ok := skBuffMembers[field]
	if !ok {
		return 0, 0, fmt.Errorf("field '%s' not found in __sk_buff struct", field)
	}

	return member[0], member[1], nil
}
