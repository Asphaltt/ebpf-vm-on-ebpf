# Copyright 2023 Leon Hwang.
# SPDX-License-Identifier: Apache-2.0

CLANG ?= clang
CCFLAG := -O2 -target bpf -g
INCLUDE := -I../../bpf/headers

fibonacci.o: fibonacci.c
	$(CLANG) $(CCFLAG) $(INCLUDE) -c $< -o $@
