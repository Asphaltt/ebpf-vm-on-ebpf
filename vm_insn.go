// SPDX-License-Identifier: Apache-2.0
// Copyright 2023 Leon Hwang.

package main

import (
	"fmt"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
)

const (
	atomicMode     = asm.XAddMode
	probeMemMode   = asm.AbsMode
	probeMemsxMode = asm.IndMode

	bpfJmp = 0x05

	bpfTailCall = 0xf0
	bpfCallArgs = 0xe0
)

func checkProgInsn(insn asm.Instruction) error {
	if insn.OpCode.Class().IsLoad() {
		if insn.Src != asm.RFP {
			return fmt.Errorf("invalid load instruction: %v", insn)
		}

		return nil
	}

	if insn.OpCode.Class().IsStore() {
		if insn.Dst != asm.RFP {
			return fmt.Errorf("invalid store instruction: %v", insn)
		}

		return nil
	}

	if insn.OpCode.Class() == asm.StXClass && insn.OpCode.Mode() == atomicMode {
		return fmt.Errorf("invalid STX_ATOMIC instruction: %v", insn)
	}

	if insn.OpCode.Class() == asm.LdXClass && (insn.OpCode.Mode() == probeMemMode || insn.OpCode.Mode() == probeMemsxMode) {
		return fmt.Errorf("invalid LDX_MEM instruction: %v", insn)
	}

	if op := byte(insn.OpCode); op == bpfJmp|bpfTailCall || op == bpfJmp|bpfCallArgs {
		return fmt.Errorf("invalid JMP TAIL_CALL|CALL_ARGS instruction: %v", insn)
	}

	if insn.OpCode.Class().IsJump() && insn.OpCode.JumpOp() == asm.Call && !insn.IsFunctionCall() {
		// Only support bpf2bpf function call.
		return fmt.Errorf("invalid JMP CALL instruction: %v", insn)
	}

	return nil
}

func checkProgDepth(insn *asm.Instruction) (int, bool) {
	if insn.OpCode.Class().IsLoad() || insn.OpCode.Class().IsStore() {
		return int(insn.Offset), true
	}

	return 0, false
}

func checkProgInsns(insns asm.Instructions) (int, error) {
	if len(insns) == 0 {
		return 0, fmt.Errorf("no instructions")
	}
	if len(insns) > maxProgInsns {
		return 0, fmt.Errorf("too many instructions: %d", len(insns))
	}

	depth := 0
	for _, insn := range insns {
		if err := checkProgInsn(insn); err != nil {
			return 0, err
		}

		if off, ok := checkProgDepth(&insn); ok {
			if off < depth {
				depth = off
			}
		}
	}

	return depth, nil
}

func splitProgInsns(prog *ebpf.ProgramSpec) []asm.Instructions {
	var insns []asm.Instructions

	offset := 0
	for i, insn := range prog.Instructions {
		if insn.Symbol() != "" && !insn.OpCode.Class().IsJump() && i != 0 {
			insns = append(insns, prog.Instructions[offset:i])
			offset = i
		}
	}

	insns = append(insns, prog.Instructions[offset:])

	// Correct the function call offset.

	funcs := make(map[string]int, len(insns))
	for i, insns := range insns {
		funcs[insns[0].Symbol()] = i
	}

	for i, insn := range prog.Instructions {
		if insn.IsFunctionCall() {
			off, ok := funcs[insn.Reference()]
			if !ok {
				panic(fmt.Errorf("invalid function call: %v", insn))
			}
			prog.Instructions[i].Constant = int64(off)
		}
	}

	return insns
}
