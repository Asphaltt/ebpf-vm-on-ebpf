// Copyright 2024 Leon Hwang.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"log"
	"unsafe"
)

func readStack(obj *vmObjects) error {
	stackMap := obj.BpfVmStacks

	stackMem := make([]byte, 2*1024*1024)

	err := stackMap.Lookup(uint32(0), stackMem)
	if err != nil {
		return fmt.Errorf("failed to read stack: %w", err)
	}

	offset := 2*1024*1024 - 40 - 1 // 1 byte for the size of the stack reserved
	fibs := unsafe.Slice((*uint32)(unsafe.Pointer(&stackMem[offset])), 10)

	log.Printf("fibs on stack: %v", fibs)

	return nil
}
