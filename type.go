// SPDX-License-Identifier: Apache-2.0
// Copyright 2023 Leon Hwang.

package main

import (
	"github.com/cilium/ebpf/asm"
)

const (
	maxProgInsns = 4 * 1024
)

// type bpfInsn struct {
// 	OpCode uint8
// 	Regs   uint8
// 	Off    int16
// 	Imm    int32
// }

type vmProg struct {
	Instructions [maxProgInsns * asm.InstructionSize]byte
	InsnCount    uint32
	StackDepth   int32
}
