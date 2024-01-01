// SPDX-License-Identifier: Apache-2.0
// Copyright 2023 Leon Hwang.

package main

import (
	"bytes"
	"encoding/binary"
	"fmt"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
)

var le binary.ByteOrder = binary.LittleEndian

func marshalInsns(insns asm.Instructions, tgt []byte) error {
	off := 0
	for _, insn := range insns {
		buf := bytes.NewBuffer(nil)
		if _, err := insn.Marshal(buf, le); err != nil {
			return fmt.Errorf("failed to marshal insn %v: %w", insn, err)
		}

		_ = copy(tgt[off:], buf.Bytes())
		off += asm.InstructionSize
	}

	return nil
}

func addVmBpfProg(vmObj *vmObjects, prog *ebpf.ProgramSpec) error {
	funcs := splitProgInsns(prog)
	if len(funcs) > 1024 {
		return fmt.Errorf("too many functions: %d (limit 1024)", len(funcs))
	}
	for i, insns := range funcs {
		depth, err := checkProgInsns(insns)
		if err != nil {
			return fmt.Errorf("invalid instructions: %w", err)
		}

		var vmProg vmProg
		vmProg.InsnCount = uint32(len(insns))
		vmProg.StackDepth = int32(depth)

		err = marshalInsns(insns, vmProg.Instructions[:])
		if err != nil {
			return fmt.Errorf("failed to marshal instructions: %w", err)
		}

		key := uint32(i)
		err = vmObj.BpfVmProgs.Put(key, &vmProg)
		if err != nil {
			return fmt.Errorf("failed to put vm prog: %w", err)
		}
	}

	if err := vmObj.BpfVmProgs.Freeze(); err != nil {
		return fmt.Errorf("failed to freeze vm progs bpf map: %w", err)
	}

	return nil
}
