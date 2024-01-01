/**
 * Copyright 2023 Leon Hwang.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "vmlinux.h"

#include "bpf/bpf_helpers.h"

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

char _license[] SEC("license") = "GPL";