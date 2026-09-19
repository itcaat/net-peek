package main

import (
	"sort"
	"strings"

	"github.com/google/gopacket/pcap"
)

func availableInterfaces() (string, error) {
	names, err := availableInterfaceNames()
	if err != nil {
		return "", err
	}
	return strings.Join(names, ", "), nil
}

func availableInterfaceNames() ([]string, error) {
	devices, err := pcap.FindAllDevs()
	if err != nil {
		return nil, err
	}
	names := make([]string, 0, len(devices)+1)
	names = append(names, "all")
	for _, dev := range devices {
		names = append(names, dev.Name)
	}
	if len(names) > 1 {
		sort.Strings(names[1:])
	}
	return names, nil
}
