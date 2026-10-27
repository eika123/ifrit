package main

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -type packet_event -cc clang -target bpf -cflags "-O2 -g -Wall -Wno-missing-declarations" filter bpf/filter.c -- -I./bpf
