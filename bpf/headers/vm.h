/* SPDX-License-Identifier: GPL-2.0 */
// Copyright 2023 Leon Hwang.

#ifndef __VM_H_
#define __VM_H_

#include "vmlinux.h"

#include "bpf/bpf_common.h"
#include "bpf/bpf_insn.h"

#include "bpf/bpf_helpers.h"

#define BPF_MAX_PROGS       1024
#define BPF_MAX_PROG_INSNS  4 * 1024
#define BPF_MAX_STACK       2 * 1024 * 1024

struct bpf_vm_prog {
    struct bpf_insn insns[BPF_MAX_PROG_INSNS];
    u32 insns_cnt;
    int32 stack_depth;
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, BPF_MAX_PROGS);
    __type(key, __u32);
    __type(value, struct bpf_vm_prog);
} bpf_vm_progs SEC(".maps");

static __always_inline struct bpf_vm_prog *
__get_bpf_vm_prog(u32 prog_idx)
{
    return bpf_map_lookup_elem(&bpf_vm_progs, &prog_idx);
}

struct bpf_vm_stack {
    u8 stack[BPF_MAX_STACK];
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct bpf_vm_stack);
} bpf_vm_stacks SEC(".maps");

static __always_inline struct bpf_vm_stack *
__get_bpf_vm_stack(void)
{
    u32 key = 0;
    return bpf_map_lookup_elem(&bpf_vm_stacks, &key);
}

enum bpf_vm_state {
    BPF_VM_STATE_UNSPEC,

    BPF_VM_STATE_VM_INTERNAL_ERR,

    BPF_VM_STATE_INSN_CALL,
    BPF_VM_STATE_INSN_PROBE_MEM,
    BPF_VM_STATE_INSN_ATOMIC,
    BPF_VM_STATE_INSN_INVALID,
};

struct bpf_vm {
    u64 reg_ip; // instruction pointer combined with prog_idx|insn_idx
    u64 regs[MAX_BPF_REG + 1]; // add 1 hidden reg

    int stack_curr_depth;
    u32 func_call_depth;
    u64 func_call_stack[BPF_MAX_PROGS];
    int stack_depth_stack[BPF_MAX_PROGS];

    enum bpf_vm_state state;
};

static __always_inline void
__vm_init(struct bpf_vm *vm)
{
    vm->reg_ip = 0;
    vm->func_call_depth = 0;
    vm->state = BPF_VM_STATE_UNSPEC;

    /* -1 is for calculating offset conveniently at LOAD_STACK() and
     * STORE_STACK() in vm.c. The offset is in range [0, BPF_MAX_STACK).
     */
    vm->stack_curr_depth = -1;
}

enum bpf_vm_action {
    BPF_VM_ACTION_ABORTED,
    BPF_VM_ACTION_CONTINUE,
    BPF_VM_ACTION_FINISH,
};

#endif // __VM_H_