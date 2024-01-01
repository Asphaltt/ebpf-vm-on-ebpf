// SPDX-License-Identifier: Apache-2.0
// Copyright 2023 Leon Hwang.

#ifndef __ATOMIC_H_
#define __ATOMIC_H_

#define atomic_add(val, ptr)            __sync_fetch_and_add(ptr, val)
#define atomic64_add(val, ptr)          __sync_fetch_and_add(ptr, val)
#define atomic_fetch_add(val, ptr)      __sync_fetch_and_add(ptr, val)
#define atomic64_fetch_add(val, ptr)    __sync_fetch_and_add(ptr, val)
#define atomic_and(val, ptr)            __sync_fetch_and_and(ptr, val)
#define atomic64_and(val, ptr)          __sync_fetch_and_and(ptr, val)
#define atomic_fetch_and(val, ptr)      __sync_fetch_and_and(ptr, val)
#define atomic64_fetch_and(val, ptr)    __sync_fetch_and_and(ptr, val)
#define atomic_or(val, ptr)             __sync_fetch_and_or(ptr, val)
#define atomic64_or(val, ptr)           __sync_fetch_and_or(ptr, val)
#define atomic_fetch_or(val, ptr)       __sync_fetch_and_or(ptr, val)
#define atomic64_fetch_or(val, ptr)     __sync_fetch_and_or(ptr, val)
#define atomic_xor(val, ptr)            __sync_fetch_and_xor(ptr, val)
#define atomic64_xor(val, ptr)          __sync_fetch_and_xor(ptr, val)
#define atomic_fetch_xor(val, ptr)      __sync_fetch_and_xor(ptr, val)
#define atomic64_fetch_xor(val, ptr)    __sync_fetch_and_xor(ptr, val)
#define atomic_xchg(ptr, new)           __sync_swap(ptr, new)
#define atomic64_xchg(ptr, new)         __sync_swap(ptr, new)
#define atomic_cmpxchg(ptr, old, new)   __sync_val_compare_and_swap(ptr, old, new)
#define atomic64_cmpxchg(ptr, old, new) __sync_val_compare_and_swap(ptr, old, new)

#endif // __ATOMIC_H_