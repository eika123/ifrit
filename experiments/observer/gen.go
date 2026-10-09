package main

//go:generate /home/uit-eindride/go/bin/bpf2go -cc clang -target bpf -cflags "-O2 -g -Wall" filter bpf/filter.c -- -I./bpf
