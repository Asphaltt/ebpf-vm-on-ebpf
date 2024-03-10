/**
 * SPDX-License-Identifier: GPL-2.0
 * Copyright 2023 Leon Hwang.
 */

#include "vmlinux.h"

#include "bpf/bpf_helpers.h"
#include "bpf/bpf_endian.h"
#include "bpf/bpf_compiler.h"

#include "vm.h"
#include "atomic.h"

static struct bpf_vm __vm;
#define vm (&__vm)

/* Registers */
#define BPF_R0  vm->regs[BPF_REG_0]
#define BPF_R1  vm->regs[BPF_REG_1]
#define BPF_R2  vm->regs[BPF_REG_2]
#define BPF_R3  vm->regs[BPF_REG_3]
#define BPF_R4  vm->regs[BPF_REG_4]
#define BPF_R5  vm->regs[BPF_REG_5]
#define BPF_R6  vm->regs[BPF_REG_6]
#define BPF_R7  vm->regs[BPF_REG_7]
#define BPF_R8  vm->regs[BPF_REG_8]
#define BPF_R9  vm->regs[BPF_REG_9]
#define BPF_R10 vm->regs[BPF_REG_10]

/* Named registers */
#define DST     vm->regs[insn->dst_reg]
#define SRC     vm->regs[insn->src_reg]
#define FP      vm->regs[BPF_REG_FP]
#define AX      vm->regs[BPF_REG_AX]
#define ARG1    vm->regs[BPF_REG_ARG1]
#define CTX     vm->regs[BPF_REG_CTX]
#define OFF     insn->off
#define IMM     insn->imm

static __always_inline struct bpf_vm_stack *
__get_stack(void)
{
    struct bpf_vm_stack *stack;

    stack = __get_bpf_vm_stack();
    if (unlikely(!stack)) {
        vm->state = BPF_VM_STATE_VM_INTERNAL_ERR;
        bpf_printk("bpf_vm: failed to prepare stack\n");
        return NULL;
    }

    return stack;
}

#define __ACCESS_STACK(typ, off)                                        \
    ({                                                                  \
        int __depth = vm->stack_curr_depth + off;                       \
        u32 __offset = BPF_MAX_STACK + __depth;                         \
        struct bpf_vm_stack *__stack;                                   \
                                                                        \
        if (unlikely(__offset + sizeof(typ) >= BPF_MAX_STACK)) {        \
            vm->state = BPF_VM_STATE_INSN_PROBE_MEM;                    \
            bpf_printk("bpf_vm: invalid stack access: offset %lu, size: %d, max stack %d\n", __offset, sizeof(typ), BPF_MAX_STACK); \
            return BPF_VM_ACTION_ABORTED;                               \
        }                                                               \
        __stack = __get_stack();                                        \
        if (unlikely(!__stack)) {                                       \
            vm->state = BPF_VM_STATE_VM_INTERNAL_ERR;                   \
            return BPF_VM_ACTION_ABORTED;                               \
        }                                                               \
        (void *)(unsigned long) (&__stack->stack[__offset]);            \
    })

/* LOAD_STACK loads sizeof(typ) memory from stack like dst = *(typ *)(src+off) */
#define LOAD_STACK(dst, src, typ, off)                                  \
    do {                                                                \
        void *ptr = __ACCESS_STACK(typ, off);                           \
        dst = *(typ *)(unsigned long) ptr;                              \
    } while(0)

/* STORE_STACK stores sizeof(typ) memory to stack like *(typ *)(dst+off) = src */
#define STORE_STACK(dst, src, typ, off)                                 \
    do {                                                                \
        void *ptr = __ACCESS_STACK(typ, off);                           \
        *(typ *)(unsigned long) ptr = src;                              \
    } while(0)

static __noinline enum bpf_vm_action
__exec_insn(struct bpf_vm_prog *prog, u32 idx)
{
    struct bpf_insn *insn, *next;
    u32 insn_idx, call_depth;
    int stack_depth;

    if (idx >= BPF_MAX_PROG_INSNS) {
        vm->state = BPF_VM_STATE_VM_INTERNAL_ERR;
        bpf_printk("bpf_vm: invalid insn_idx: %u (cnt %d)\n", idx, prog->insns_cnt);
        return BPF_VM_ACTION_ABORTED;
    }

    insn = &prog->insns[idx];
    switch (insn->code) {
    /* ALU (shifts) */
#define SHT(OPCODE, OP)                         \
    case BPF_ALU64|BPF_##OPCODE|BPF_X:          \
        DST = DST OP (SRC & 63);                \
        break;                                  \
    case BPF_ALU|BPF_##OPCODE|BPF_X:            \
        DST = (u32) DST OP ((u32) SRC & 31);    \
        break;                                  \
    case BPF_ALU64|BPF_##OPCODE|BPF_K:          \
        DST = DST OP IMM;                       \
        break;                                  \
    case BPF_ALU|BPF_##OPCODE|BPF_K:            \
        DST = (u32) DST OP (u32) IMM;           \
        break;
    /* ALU (rest) */
#define ALU(OPCODE, OP)                         \
    case BPF_ALU64|BPF_##OPCODE|BPF_X:          \
        DST = DST OP SRC;                       \
        break;                                  \
    case BPF_ALU|BPF_##OPCODE|BPF_X:            \
        DST = (u32) DST OP (u32) SRC;           \
        break;                                  \
    case BPF_ALU64|BPF_##OPCODE|BPF_K:          \
        DST = DST OP IMM;                       \
        break;                                  \
    case BPF_ALU|BPF_##OPCODE|BPF_K:            \
        DST = (u32) DST OP (u32) IMM;           \
        break;
    ALU(ADD,  +)
    ALU(SUB,  -)
    ALU(AND,  &)
    ALU(OR,   |)
    ALU(XOR,  ^)
    ALU(MUL,  *)
    SHT(LSH, <<)
    SHT(RSH, >>)
#undef SHT
#undef ALU
    case BPF_ALU|BPF_NEG:
        DST = (u32) -DST;
        break;
    case BPF_ALU64|BPF_NEG:
        DST = -DST;
        break;
    case BPF_ALU|BPF_MOV|BPF_X:
        switch (OFF) {
        case 0:
            DST = (u32) SRC;
            break;
        case 8:
            DST = (u32)(s8) SRC;
            break;
        case 16:
            DST = (u32)(s16) SRC;
            break;
        }
        break;
    case BPF_ALU|BPF_MOV|BPF_K:
        DST = (u32) IMM;
        break;
    case BPF_ALU64|BPF_MOV|BPF_X:
        switch (OFF) {
        case 0:
            DST = SRC;
            break;
        case 8:
            DST = (s8) SRC;
            break;
        case 16:
            DST = (s16) SRC;
            break;
        case 32:
            DST = (s32) SRC;
            break;
        }
        break;
    case BPF_ALU64|BPF_MOV|BPF_K:
        DST = IMM;
        break;
    case BPF_LD|BPF_IMM|BPF_DW:
        vm->reg_ip++;
        insn_idx = (u32) vm->reg_ip;
        if (unlikely(insn_idx >= BPF_MAX_PROG_INSNS || insn_idx >= prog->insns_cnt)) {
            vm->state = BPF_VM_STATE_VM_INTERNAL_ERR;
            bpf_printk("bpf_vm: invalid insn_idx: %u (cnt %d)\n", insn_idx, prog->insns_cnt);
            return BPF_VM_ACTION_ABORTED;
        }

        if (likely(insn_idx < BPF_MAX_PROG_INSNS)) {
            /* We're sure the insn_idx is valid, but verifier is not sure. */
            next = &prog->insns[insn_idx];
            DST = (u64) (u32) insn->imm | ((u64) (u32) next->imm) << 32;
        }
        break;
    case BPF_ALU|BPF_ARSH|BPF_X:
        DST = (u64) (u32) (((s32) DST) >> (SRC & 31));
        break;
    case BPF_ALU|BPF_ARSH|BPF_K:
        DST = (u64) (u32) (((s32) DST) >> IMM);
        break;
    case BPF_ALU64|BPF_ARSH|BPF_X:
        (*(s64 *) &DST) >>= (SRC & 63);
        break;
    case BPF_ALU64|BPF_ARSH|BPF_K:
        (*(s64 *) &DST) >>= IMM;
        break;
    case BPF_ALU64|BPF_MOD|BPF_X:
        switch (OFF) {
        case 0:
            // div64_u64_rem(DST, SRC, &AX);
            DST = DST % SRC;
            break;
        case 1:
            // AX = div64_s64(DST, SRC);
            AX = DST % SRC;
            DST = DST - AX * SRC;
            break;
        }
        break;
    case BPF_ALU|BPF_MOD|BPF_X:
        switch (OFF) {
        case 0:
            // DST = do_div(AX, (u32) SRC);
            DST = (u32) DST % (u32) SRC;
            break;
        case 1:
            // AX = abs((s32)DST);
            AX = ((s32) DST) < 0 ? -AX : AX;
            // AX = do_div(AX, abs((s32)SRC));
            AX = (s32) AX % ((s32) SRC < 0 ? -SRC : SRC);
            if ((s32)DST < 0)
                DST = (u32)-AX;
            else
                DST = (u32)AX;
            break;
        }
        break;
    case BPF_ALU64|BPF_MOD|BPF_K:
        switch (OFF) {
        case 0:
            // div64_u64_rem(DST, IMM, &AX);
            // DST = AX;
            DST = DST % IMM;
            break;
        case 1:
            // AX = div64_s64(DST, IMM);
            AX = DST % IMM;
            DST = DST - AX * IMM;
            break;
        }
        break;
    case BPF_ALU|BPF_MOD|BPF_K:
        switch (OFF) {
        case 0:
            AX = (u32) DST;
            // DST = do_div(AX, (u32) IMM);
            DST = (u32) AX % (u32) IMM;
            break;
        case 1:
            // AX = abs((s32)DST);
            AX = (s32) DST < 0 ? -DST : DST;
            // AX = do_div(AX, abs((s32)IMM));
            AX = (u32) AX % (u32) ((s32) IMM < 0 ? -IMM : IMM);
            if ((s32)DST < 0)
                DST = (u32)-AX;
            else
                DST = (u32)AX;
            break;
        }
        break;
    case BPF_ALU64|BPF_DIV|BPF_X:
        switch (OFF) {
        case 0:
            // DST = div64_u64(DST, SRC);
            DST %= SRC;
            break;
        case 1:
            // DST = div64_s64(DST, SRC);
            AX = (s64) DST < 0 ? -DST : DST;
            DST = (u64) AX % (u64) ((s64) SRC < 0 ? -SRC : SRC);
            break;
        }
        break;
    case BPF_ALU|BPF_DIV|BPF_X:
        switch (OFF) {
        case 0:
            // AX = (u32) DST;
            // do_div(AX, (u32) SRC);
            // DST = (u32) AX;
            DST = (u32) DST % (u32) SRC;
            break;
        case 1:
            // AX = abs((s32)DST);
            AX = (s32) DST < 0 ? -DST : DST;
            // do_div(AX, abs((s32)SRC));
            AX = (s32) AX % ((s32) SRC < 0 ? -SRC : SRC);
            if (((s32)DST < 0) == ((s32)SRC < 0))
                DST = (u32)AX;
            else
                DST = (u32)-AX;
            break;
        }
        break;
    case BPF_ALU64|BPF_DIV|BPF_K:
        switch (OFF) {
        case 0:
            // DST = div64_u64(DST, IMM);
            DST %= IMM;
            break;
        case 1:
            // DST = div64_s64(DST, IMM);
            AX = (s64) DST < 0 ? -DST : DST;
            DST = (u64) AX % (u64) ((s64) IMM < 0 ? -IMM : IMM);
            break;
        }
        break;
    case BPF_ALU|BPF_DIV|BPF_K:
        switch (OFF) {
        case 0:
            AX = (u32) DST;
            // do_div(AX, (u32) IMM);
            AX = (u32) AX % (u32) IMM;
            DST = (u32) AX;
            break;
        case 1:
            // AX = abs((s32)DST);
            AX = (s32) DST < 0 ? -DST : DST;
            // do_div(AX, abs((s32)IMM));
            AX = (u32) AX % (u32) ((s32) IMM < 0 ? -IMM : IMM);
            if (((s32)DST < 0) == ((s32)IMM < 0))
                DST = (u32)AX;
            else
                DST = (u32)-AX;
            break;
        }
        break;
    case BPF_ALU|BPF_END|BPF_TO_BE:
        switch (IMM) {
        case 16:
            DST = bpf_htons(DST);
            break;
        case 32:
            DST = bpf_htonl(DST);
            break;
        case 64:
            DST = bpf_cpu_to_be64(DST);
            break;
        }
        break;
    case BPF_ALU|BPF_END|BPF_TO_LE:
        // LE by default
        switch (IMM) {
        case 16:
            DST = (DST);
            break;
        case 32:
            DST = (DST);
            break;
        case 64:
            DST = (DST);
            break;
        }
        break;
    case BPF_ALU64|BPF_END|BPF_TO_LE:
        switch (IMM) {
        case 16:
            DST = ___bpf_swab16(DST);
            break;
        case 32:
            DST = ___bpf_swab32(DST);
            break;
        case 64:
            DST = ___bpf_swab64(DST);
            break;
        }
        break;

    /* CALL */
    case BPF_JMP|BPF_CALL:
        /* Only support bpf2bpf function call with SRC == R1 */
        if (unlikely(insn->src_reg != BPF_REG_1)) {
            vm->state = BPF_VM_STATE_INSN_CALL;
            return BPF_VM_ACTION_ABORTED;
        }

        call_depth = vm->func_call_depth++;
        if (likely(call_depth < BPF_MAX_PROGS)) {
            vm->func_call_stack[call_depth] = vm->reg_ip;
            vm->stack_depth_stack[call_depth] = vm->stack_curr_depth;
            vm->stack_curr_depth += prog->stack_depth;
            vm->reg_ip = ((u64) IMM) << 32;
        } else {
            vm->state = BPF_VM_STATE_VM_INTERNAL_ERR;
            bpf_printk("bpf_vm: invalid func_call_depth: %u\n", vm->func_call_depth);
            return BPF_VM_ACTION_ABORTED;
        }
        break;
    case BPF_JMP|BPF_CALL_ARGS:
    case BPF_JMP|BPF_TAIL_CALL:
        vm->state = BPF_VM_STATE_INSN_CALL;
        return BPF_VM_ACTION_ABORTED;
    case BPF_JMP|BPF_JA:
        vm->reg_ip += OFF;
        break;
    case BPF_JMP32|BPF_JA:
        vm->reg_ip += IMM;
        break;
    case BPF_JMP|BPF_EXIT:
        // bpf_printk("bpf_vm: exit call_depth=%u\n", vm->func_call_depth);
        if (vm->func_call_depth == 0)
            return BPF_VM_ACTION_FINISH;

        call_depth = --vm->func_call_depth;
        if (unlikely(call_depth >= BPF_MAX_PROGS)) {
            vm->state = BPF_VM_STATE_VM_INTERNAL_ERR;
            bpf_printk("bpf_vm: invalid func_call_depth: %u\n", vm->func_call_depth);
            return BPF_VM_ACTION_ABORTED;
        }

        // restore IP
        vm->reg_ip = vm->func_call_stack[call_depth];
        vm->func_call_stack[call_depth] = 0;

        // restore stack depth
        stack_depth = vm->stack_depth_stack[call_depth];
        vm->stack_depth_stack[call_depth] = 0;
        vm->stack_curr_depth = stack_depth;
        break;

    /* JMP */
#define COND_JMP(SIGN, OPCODE, CMP_OP)              \
    case BPF_JMP|BPF_##OPCODE|BPF_X:                \
        if ((SIGN##64) DST CMP_OP (SIGN##64) SRC) { \
            vm->reg_ip += OFF;                      \
            break;                                  \
        }                                           \
    case BPF_JMP32|BPF_##OPCODE|BPF_X:              \
        if ((SIGN##32) DST CMP_OP (SIGN##32) SRC) { \
            vm->reg_ip += OFF;                      \
            break;                                  \
        }                                           \
    case BPF_JMP|BPF_##OPCODE|BPF_K:                \
        if ((SIGN##64) DST CMP_OP (SIGN##64) IMM) { \
            vm->reg_ip += OFF;                      \
            break;                                  \
        }                                           \
    case BPF_JMP32|BPF_##OPCODE|BPF_K:              \
        if ((SIGN##32) DST CMP_OP (SIGN##32) IMM) { \
            vm->reg_ip += OFF;                      \
            break;                                  \
        }
    COND_JMP(u, JEQ, ==)
    COND_JMP(u, JNE, !=)
    COND_JMP(u, JGT, >)
    COND_JMP(u, JLT, <)
    COND_JMP(u, JGE, >=)
    COND_JMP(u, JLE, <=)
    COND_JMP(u, JSET, &)
    COND_JMP(s, JSGT, >)
    COND_JMP(s, JSLT, <)
    COND_JMP(s, JSGE, >=)
    COND_JMP(s, JSLE, <=)
#undef COND_JMP

    /* ST, STX and LDX */
    case BPF_ST|BPF_NOSPEC:
        break;
#define LDST(SIZEOP, SIZE)                                                  \
    case BPF_STX|BPF_MEM|BPF_##SIZEOP:                                      \
        /* *(SIZE *)(unsigned long) (DST + insn->off) = SRC; */             \
        STORE_STACK(DST, SRC, SIZE, insn->off);                             \
        break;                                                              \
    case BPF_ST|BPF_MEM|BPF_##SIZEOP:                                       \
        /* *(SIZE *)(unsigned long) (DST + insn->off) = IMM; */             \
        STORE_STACK(DST, IMM, SIZE, insn->off);                             \
        break;                                                              \
    case BPF_LDX|BPF_MEM|BPF_##SIZEOP:                                      \
        /* DST = *(SIZE *)(unsigned long) (SRC + insn->off); */             \
        LOAD_STACK(DST, sizeof(SIZE), SIZE, insn->off);                     \
        break;                                                              \
    case BPF_LDX|BPF_PROBE_MEM|BPF_##SIZEOP:                                \
        vm->state = BPF_VM_STATE_INSN_PROBE_MEM;                            \
        bpf_printk("bpf_vm: invalid probe mem insn\n");                     \
        return BPF_VM_ACTION_ABORTED;

    LDST(B,   u8)
    LDST(H,  u16)
    LDST(W,  u32)
    LDST(DW, u64)
#undef LDST

#define LDSX(SIZEOP, SIZE)                                                  \
    case BPF_LDX|BPF_MEMSX|BPF_##SIZEOP:                                    \
        /* DST = *(SIZE *)(unsigned long) (SRC + insn->off); */             \
        LOAD_STACK(DST, sizeof(SIZE), SIZE, insn->off);                     \
        break;                                                              \
    case BPF_LDX|BPF_PROBE_MEMSX|BPF_##SIZEOP:                              \
        vm->state = BPF_VM_STATE_INSN_PROBE_MEM;                            \
        bpf_printk("bpf_vm: invalid probe memsx insn\n");                   \
        return BPF_VM_ACTION_ABORTED;

    LDSX(B,   s8)
    LDSX(H,  s16)
    LDSX(W,  s32)
#undef LDSX

#undef LD_STACK
#undef ST_STACK

// #define ATOMIC_ALU_OP(BOP, KOP)                                         \
//         case BOP:                                                       \
//             if (BPF_SIZE(insn->code) == BPF_W)                          \
//                 atomic_##KOP((u32) SRC, (u64 *)(unsigned long)     \
//                          (DST + insn->off));                            \
//             else                                                        \
//                 atomic64_##KOP((u64) SRC, (u64 *)(unsigned long) \
//                            (DST + insn->off));                          \
//             break;                                                      \
//         case BOP | BPF_FETCH:                                           \
//             if (BPF_SIZE(insn->code) == BPF_W)                          \
//                 SRC = (u32) atomic_fetch_##KOP(                         \
//                     (u32) SRC,                                          \
//                     (u64 *)(unsigned long) (DST + insn->off));     \
//             else                                                        \
//                 SRC = (u64) atomic64_fetch_##KOP(                       \
//                     (u64) SRC,                                          \
//                     (u64 *)(unsigned long) (DST + insn->off));   \
//             break;

    case BPF_STX|BPF_ATOMIC|BPF_DW:
    case BPF_STX|BPF_ATOMIC|BPF_W:
        vm->state = BPF_VM_STATE_INSN_ATOMIC;
        bpf_printk("bpf_vm: invalid atomic insn\n");
        return BPF_VM_ACTION_ABORTED;
//         switch (IMM) {
//         ATOMIC_ALU_OP(BPF_ADD, add)
//         ATOMIC_ALU_OP(BPF_AND, and)
//         ATOMIC_ALU_OP(BPF_OR, or)
//         ATOMIC_ALU_OP(BPF_XOR, xor)
// #undef ATOMIC_ALU_OP

//         case BPF_XCHG:
//             if (BPF_SIZE(insn->code) == BPF_W)
//                 SRC = (u32) atomic_xchg(
//                     (u64 *)(unsigned long) (DST + insn->off),
//                     (u32) SRC);
//             else
//                 SRC = (u64) atomic64_xchg(
//                     (u64 *)(unsigned long) (DST + insn->off),
//                     (u64) SRC);
//             break;
//         case BPF_CMPXCHG:
//             if (BPF_SIZE(insn->code) == BPF_W)
//                 BPF_R0 = (u32) atomic_cmpxchg(
//                     (u64 *)(unsigned long) (DST + insn->off),
//                     (u32) BPF_R0, (u32) SRC);
//             else
//                 BPF_R0 = (u64) atomic64_cmpxchg(
//                     (u64 *)(unsigned long) (DST + insn->off),
//                     (u64) BPF_R0, (u64) SRC);
//             break;

//         default:
//             goto default_label;
//         }
//         break;

    default:
        goto default_label;
    }

    return BPF_VM_ACTION_CONTINUE;

default_label:
    vm->state = BPF_VM_STATE_INSN_INVALID;
    bpf_printk("bpf_vm: unknown opcode :%02x (imm: 0x%x)\n", insn->code, IMM);
    return BPF_VM_ACTION_ABORTED;
}

static __noinline enum bpf_vm_action
__vm_run(struct bpf_vm_prog *prog)
{
    u32 insn_idx;

    insn_idx = (u32) vm->reg_ip;

    if (insn_idx >= prog->insns_cnt) {
        vm->state = BPF_VM_STATE_VM_INTERNAL_ERR;
        bpf_printk("bpf_vm: invalid insn_idx: %u (cnt %d)\n", insn_idx, prog->insns_cnt);
        return BPF_VM_ACTION_ABORTED;
    }

    vm->reg_ip++;
    return __exec_insn(prog, insn_idx);
}

static __always_inline int
run_vm(void)
{
    u32 prog_idx, prev_prog_idx;
    struct bpf_vm_prog *prog;
    enum bpf_vm_action ret;

    prev_prog_idx = prog_idx = (u32) (vm->reg_ip >> 32);
    prog = __get_bpf_vm_prog(prog_idx);
    if (unlikely(!prog)) {
        vm->state = BPF_VM_STATE_VM_INTERNAL_ERR;
        bpf_printk("bpf_vm: invalid prog_idx: %u\n", prog_idx);
        return BPF_VM_ACTION_ABORTED;
    }

    for (u32 i = 0; i < 100; i++) {
        ret = __vm_run(prog);
        if (unlikely(ret != BPF_VM_ACTION_CONTINUE))
            return ret;

        prog_idx = (u32) (vm->reg_ip >> 32);
        if (likely(prog_idx == prev_prog_idx))
            continue;

        prog = __get_bpf_vm_prog(prog_idx);
        if (unlikely(!prog)) {
            vm->state = BPF_VM_STATE_VM_INTERNAL_ERR;
            bpf_printk("bpf_vm: invalid prog_idx: %u\n", prog_idx);
            return BPF_VM_ACTION_ABORTED;
        }

        prev_prog_idx = prog_idx;
    }

    return BPF_VM_ACTION_CONTINUE;
}

struct bpf_vm_ctx {
    enum bpf_vm_action action;
};

static long
__vm_loop_callback(__u32 index, struct bpf_vm_ctx *ctx)
{
    if (!ctx)
        return 1;

    ctx->action = run_vm();

    return ctx->action == BPF_VM_ACTION_CONTINUE ? 0 : 1;
}

static __always_inline bool
__vm_loop(void)
{
    struct bpf_vm_ctx ctx = {};

    bpf_loop(BPF_MAX_LOOPS, __vm_loop_callback, &ctx, 0);

    return ctx.action == BPF_VM_ACTION_FINISH;
}

static __always_inline bool
__vm_entry(void)
{
    bool ret;

    __vm_init(vm);

    ret = __vm_loop();

    bpf_printk("bpf_vm: R0=%llu state=%d\n", BPF_R0, vm->state);

    return ret;
}

SEC("xdp")
int bpf_vm_xdp(struct xdp_md *ctx)
{
    struct ethhdr *eth;
    struct iphdr *iph;

    eth = (struct ethhdr *) (unsigned long) ctx->data;
    iph = (struct iphdr *) (eth + 1);
    if ((void *) (iph + 1) > (void *) (unsigned long) ctx->data_end)
        return XDP_ABORTED;

#define ETH_P_IP        0x0800          /* Internet Protocol packet     */
    if (unlikely(eth->h_proto != bpf_htons(ETH_P_IP)))
        return XDP_PASS;

    if (likely(iph->ttl != 1))
        return XDP_PASS;

    return __vm_entry() ? XDP_PASS : XDP_ABORTED;
}

char __license[] SEC("license") = "GPL";
