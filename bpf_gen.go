//go:build linux

package main

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -no-strip -target bpfel -tags linux bpf bpf/netpeek.c -- -I./bpf/headers
