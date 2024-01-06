# Build a feature-less eBPF vm on eBPF

If bpf prog can run for long time, what do you want to do?

I want to build an eBPF vm on eBPF, even though it's a feature-less
vm, just for fun.

## What is eBPF vm on eBPF?

eBPF vm on eBPF is an eBPF vm, which is implemented by eBPF. As a result, this
vm is able to reuse most existing eBPF instructions, and then execute
the instruction one by one by interpreter way.

After implementing this vm, there are following instructions unsupported:

- `BPF_PROBE_MEM` related instructions
- atomic related instructions
- non-bpf2bpf call related instructions, including tailcall

Unlike ebpf, eBPF vm on eBPF is unable to access the memory directly, so it limits to access specified stack memory only. As a result, it is unable to support
bpf maps and bpf helpers. This is the reason why it is a feature-less eBPF vm.

## How to build eBPF vm on eBPF?

eBPF vm on eBPF is a vm, which combines with following parts:

- Programs part: it caches bpf progs to be executed.
- Stack memory space: it is used to store temporary data.
- Registers: it is used to store temporary variables.
- Interpreter: it is used to execute bpf instructions one by one.

And, the bpf instructions limit to operate stack memory space and registers.

## How about function call?

Can eBPF vm on eBPF support function call? The answer is yes, but it supports
bpf2bpf funcation call only.

It does not support tailcall, because it is unable to access bpf maps and call
bpf helpers.

As we know, in bpf C code, `__noinline` indicates that the function is not to be
inlined while compiling. So, if we want to call a function in this vm, we need
to add `__noinline` to the callee function.

As a result, after we manipulate bpf2bpf function calls relationship in user
space, we save them to programs part of the vm. Then, when the vm executes the
CALL instruction:

- cache current instruction position
- cache current stack pointer
- adjust stack pointer
- jump to the callee function

When the callee function returns, the vm executes the RET instruction:

- restore stack pointer
- restore instruction position
- jump to the next instruction

When the vm executes the RET instruction, it has to recognize whether the
caller function is the main function or not. If it is the main function, the vm
should exit immediately.

## Calculate Fibonacci numbers with eBPF vm on eBPF

How about calculating Fibonacci numbers with eBPF vm on eBPF? The answer is yes.

```c
SEC("xdp")
int xdp_fib(struct xdp_md *ctx)
{
    volatile int fibs[10];
    fibs[0] = 1;
    fibs[1] = 1;

    for (int i = 2; i < 10; i++) {
        fibs[i] = fibs[i - 1] + fibs[i - 2];
    }

    return fibs[9];
}
```

After compiling the above bpf C code with clang, dump the object file with
[cilium/ebpf dump](https://pkg.go.dev/github.com/cilium/ebpf@v0.12.3/asm#Instructions.Format):

```asm
xdp_fib:
      ; int xdp_fib(struct xdp_md *ctx)
     0: MovImm dst: r1 imm: 1
      ; fibs[0] = 1;
     1: StXMemW dst: rfp src: r1 off: -4 imm: 0
      ; fibs[1] = 1;
     2: StXMemW dst: rfp src: r1 off: -8 imm: 0
      ; fibs[i] = fibs[i - 1] + fibs[i - 2];
     3: LdXMemW dst: r1 src: rfp off: -8 imm: 0
      ; fibs[i] = fibs[i - 1] + fibs[i - 2];
     4: LdXMemW dst: r2 src: rfp off: -4 imm: 0
      ; fibs[i] = fibs[i - 1] + fibs[i - 2];
     5: AddReg dst: r2 src: r1
      ; fibs[i] = fibs[i - 1] + fibs[i - 2];
     6: StXMemW dst: rfp src: r2 off: -12 imm: 0
      ; fibs[i] = fibs[i - 1] + fibs[i - 2];
     7: LdXMemW dst: r1 src: rfp off: -12 imm: 0
      ; fibs[i] = fibs[i - 1] + fibs[i - 2];
     8: LdXMemW dst: r2 src: rfp off: -8 imm: 0
      ; fibs[i] = fibs[i - 1] + fibs[i - 2];
     9: AddReg dst: r2 src: r1
      ; fibs[i] = fibs[i - 1] + fibs[i - 2];
    10: StXMemW dst: rfp src: r2 off: -16 imm: 0
      ; fibs[i] = fibs[i - 1] + fibs[i - 2];
    11: LdXMemW dst: r1 src: rfp off: -16 imm: 0
      ; fibs[i] = fibs[i - 1] + fibs[i - 2];
    12: LdXMemW dst: r2 src: rfp off: -12 imm: 0
      ; fibs[i] = fibs[i - 1] + fibs[i - 2];
    13: AddReg dst: r2 src: r1
      ; fibs[i] = fibs[i - 1] + fibs[i - 2];
    14: StXMemW dst: rfp src: r2 off: -20 imm: 0
      ; fibs[i] = fibs[i - 1] + fibs[i - 2];
    15: LdXMemW dst: r1 src: rfp off: -20 imm: 0
      ; fibs[i] = fibs[i - 1] + fibs[i - 2];
    16: LdXMemW dst: r2 src: rfp off: -16 imm: 0
      ; fibs[i] = fibs[i - 1] + fibs[i - 2];
    17: AddReg dst: r2 src: r1
      ; fibs[i] = fibs[i - 1] + fibs[i - 2];
    18: StXMemW dst: rfp src: r2 off: -24 imm: 0
      ; fibs[i] = fibs[i - 1] + fibs[i - 2];
    19: LdXMemW dst: r1 src: rfp off: -24 imm: 0
      ; fibs[i] = fibs[i - 1] + fibs[i - 2];
    20: LdXMemW dst: r2 src: rfp off: -20 imm: 0
      ; fibs[i] = fibs[i - 1] + fibs[i - 2];
    21: AddReg dst: r2 src: r1
      ; fibs[i] = fibs[i - 1] + fibs[i - 2];
    22: StXMemW dst: rfp src: r2 off: -28 imm: 0
      ; fibs[i] = fibs[i - 1] + fibs[i - 2];
    23: LdXMemW dst: r1 src: rfp off: -28 imm: 0
      ; fibs[i] = fibs[i - 1] + fibs[i - 2];
    24: LdXMemW dst: r2 src: rfp off: -24 imm: 0
      ; fibs[i] = fibs[i - 1] + fibs[i - 2];
    25: AddReg dst: r2 src: r1
      ; fibs[i] = fibs[i - 1] + fibs[i - 2];
    26: StXMemW dst: rfp src: r2 off: -32 imm: 0
      ; fibs[i] = fibs[i - 1] + fibs[i - 2];
    27: LdXMemW dst: r1 src: rfp off: -32 imm: 0
      ; fibs[i] = fibs[i - 1] + fibs[i - 2];
    28: LdXMemW dst: r2 src: rfp off: -28 imm: 0
      ; fibs[i] = fibs[i - 1] + fibs[i - 2];
    29: AddReg dst: r2 src: r1
      ; fibs[i] = fibs[i - 1] + fibs[i - 2];
    30: StXMemW dst: rfp src: r2 off: -36 imm: 0
      ; fibs[i] = fibs[i - 1] + fibs[i - 2];
    31: LdXMemW dst: r1 src: rfp off: -36 imm: 0
      ; fibs[i] = fibs[i - 1] + fibs[i - 2];
    32: LdXMemW dst: r2 src: rfp off: -32 imm: 0
      ; fibs[i] = fibs[i - 1] + fibs[i - 2];
    33: AddReg dst: r2 src: r1
      ; fibs[i] = fibs[i - 1] + fibs[i - 2];
    34: StXMemW dst: rfp src: r2 off: -40 imm: 0
      ; return fibs[9];
    35: LdXMemW dst: r0 src: rfp off: -40 imm: 0
    36: Exit
```

After saving the above instructions to the programs part of the vm, the vm
executes the instructions one by one, and then gets the result:

```bash
bpf_trace_printk: bpf_vm: R0=55
```

How about using bpf2bpf function call?

```c
static __noinline int
__add(int a, int b)
{
    volatile int sum = a + b;
    return sum;
}

SEC("xdp")
int xdp_fib2(struct xdp_md *ctx)
{
    volatile int fibs[10];
    fibs[0] = 1;
    fibs[1] = 1;

    for (int i = 2; i < 10; i++) {
        fibs[i] = __add(fibs[i - 1], fibs[i - 2]);
    }

    return fibs[9];
}
```

After compiling the above bpf C code with clang, dump the object file with
[cilium/ebpf dump](https://pkg.go.dev/github.com/cilium/ebpf@v0.12.3/asm#Instructions.Format):

```asm
xdp_fib2:
      ; int xdp_fib2(struct xdp_md *ctx)
     0: MovImm dst: r1 imm: 1
      ; fibs[0] = 1;
     1: StXMemW dst: rfp src: r1 off: -4 imm: 0
      ; fibs[1] = 1;
     2: StXMemW dst: rfp src: r1 off: -8 imm: 0
      ; fibs[i] = __add(fibs[i - 1], fibs[i - 2]);
     3: LdXMemW dst: r1 src: rfp off: -8 imm: 0
     4: LdXMemW dst: r2 src: rfp off: -4 imm: 0
     5: Call -1 <__add>
      ; fibs[i] = __add(fibs[i - 1], fibs[i - 2]);
     6: StXMemW dst: rfp src: r0 off: -12 imm: 0
      ; fibs[i] = __add(fibs[i - 1], fibs[i - 2]);
     7: LdXMemW dst: r1 src: rfp off: -12 imm: 0
     8: LdXMemW dst: r2 src: rfp off: -8 imm: 0
     9: Call -1 <__add>
      ; fibs[i] = __add(fibs[i - 1], fibs[i - 2]);
    10: StXMemW dst: rfp src: r0 off: -16 imm: 0
      ; fibs[i] = __add(fibs[i - 1], fibs[i - 2]);
    11: LdXMemW dst: r1 src: rfp off: -16 imm: 0
    12: LdXMemW dst: r2 src: rfp off: -12 imm: 0
    13: Call -1 <__add>
      ; fibs[i] = __add(fibs[i - 1], fibs[i - 2]);
    14: StXMemW dst: rfp src: r0 off: -20 imm: 0
      ; fibs[i] = __add(fibs[i - 1], fibs[i - 2]);
    15: LdXMemW dst: r1 src: rfp off: -20 imm: 0
    16: LdXMemW dst: r2 src: rfp off: -16 imm: 0
    17: Call -1 <__add>
      ; fibs[i] = __add(fibs[i - 1], fibs[i - 2]);
    18: StXMemW dst: rfp src: r0 off: -24 imm: 0
      ; fibs[i] = __add(fibs[i - 1], fibs[i - 2]);
    19: LdXMemW dst: r1 src: rfp off: -24 imm: 0
    20: LdXMemW dst: r2 src: rfp off: -20 imm: 0
    21: Call -1 <__add>
      ; fibs[i] = __add(fibs[i - 1], fibs[i - 2]);
    22: StXMemW dst: rfp src: r0 off: -28 imm: 0
      ; fibs[i] = __add(fibs[i - 1], fibs[i - 2]);
    23: LdXMemW dst: r1 src: rfp off: -28 imm: 0
    24: LdXMemW dst: r2 src: rfp off: -24 imm: 0
    25: Call -1 <__add>
      ; fibs[i] = __add(fibs[i - 1], fibs[i - 2]);
    26: StXMemW dst: rfp src: r0 off: -32 imm: 0
      ; fibs[i] = __add(fibs[i - 1], fibs[i - 2]);
    27: LdXMemW dst: r1 src: rfp off: -32 imm: 0
    28: LdXMemW dst: r2 src: rfp off: -28 imm: 0
    29: Call -1 <__add>
      ; fibs[i] = __add(fibs[i - 1], fibs[i - 2]);
    30: StXMemW dst: rfp src: r0 off: -36 imm: 0
      ; fibs[i] = __add(fibs[i - 1], fibs[i - 2]);
    31: LdXMemW dst: r1 src: rfp off: -36 imm: 0
    32: LdXMemW dst: r2 src: rfp off: -32 imm: 0
    33: Call -1 <__add>
      ; fibs[i] = __add(fibs[i - 1], fibs[i - 2]);
    34: StXMemW dst: rfp src: r0 off: -40 imm: 0
      ; return fibs[9];
    35: LdXMemW dst: r0 src: rfp off: -40 imm: 0
    36: Exit
__add:
      ; volatile int sum = a + b;
    37: AddReg dst: r2 src: r1
      ; volatile int sum = a + b;
    38: StXMemW dst: rfp src: r2 off: -4 imm: 0
      ; return sum;
    39: LdXMemW dst: r0 src: rfp off: -4 imm: 0
    40: Exit
```

It is used to verify whether the vm supports bpf2bpf function call or not.

After saving the above instructions to the programs part of the vm, the vm
executes the instructions one by one, and then gets the result:

```bash
bpf_trace_printk: bpf_vm: R0=55
```

## Is eBPF vm on eBPF useful?

It seems useless.

The issues that can be resolved by eBPF vm on eBPF, can be resolved by eBPF,
too.

But, without strict verification, the vm is able to execute any bpf code which
is compiled by clang. As a result, it is able to execute malicious bpf code,
which is compiled by clang, too.

Can this vm execute many bpf instructions?

Yes, by using `bpf_loop()` helper to run for long time.

## Comments

eBPF vm on eBPF is a really insteresting idea. I've implemented its demo to run
the above Fibonacci numbers calculating bpf code.

Just for fun.

## Licenses

**Apache 2.0** license for Go code.
**GPL 2.0** license for bpf code.
