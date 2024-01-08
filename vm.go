// SPDX-License-Identifier: Apache-2.0
// Copyright 2023 Leon Hwang.

package main

import (
	"context"
	"errors"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/spf13/cobra"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang vm ./bpf/vm.c -- -D__TARGET_ARCH_x86 -I./bpf/headers -Wall

var flags struct {
	device string
}

var rootCmd = &cobra.Command{
	Use: "vm",
}

func main() {
	_ = rootCmd.Execute()
}

func init() {
	rootCmd.Run = func(cmd *cobra.Command, args []string) {
		runVm()
	}

	flag := rootCmd.PersistentFlags()
	flag.StringVarP(&flags.device, "device", "d", "", "device name")
}

func runVm() {
	ifi, err := net.InterfaceByName(flags.device)
	if err != nil {
		log.Fatalf("Failed to fetch device info of %s: %v", flags.device, err)
	}

	spec, err := loadVm()
	if err != nil {
		log.Fatalf("Failed to load bpf-vm bpf spec: %v", err)
	}

	var obj vmObjects
	if err := spec.LoadAndAssign(&obj, &ebpf.CollectionOptions{
		Programs: ebpf.ProgramOptions{
			LogSize: 100 * ebpf.DefaultVerifierLogSize,
		},
	}); err != nil {
		var ve *ebpf.VerifierError
		if errors.As(err, &ve) {
			log.Fatalf("Failed to load bpf-vm bpf obj: %v\n%+v", err, ve)
		}
		log.Fatalf("Failed to load bpf-vm bpf obj: %v", err)
	}
	defer obj.Close()

	objFile := "./examples/bpf/fibonacci.o"
	spec, err = ebpf.LoadCollectionSpec(objFile)
	if err != nil {
		log.Fatalf("Failed to load fibonacci bpf spec: %v", err)
	}

	prog := spec.Programs["xdp_fib2"]

	if err := addVmBpfProg(&obj, prog); err != nil {
		log.Fatalf("Failed to inject fibonacci: %v", err)
	}

	xdp, err := link.AttachXDP(link.XDPOptions{
		Program:   obj.BpfVmXdp,
		Interface: ifi.Index,
		Flags:     link.XDPGenericMode,
	})
	if err != nil {
		log.Fatalf("Failed to attach bpf-vm to %s: %v", flags.device, err)
	}
	defer xdp.Close()

	log.Printf("bpf-vm is running on %s\n", flags.device)
	defer readStack(&obj)

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	<-ctx.Done()
}
