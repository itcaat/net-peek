package main

import "fmt"

func humanBytes(v float64) string {
	units := []string{"B", "KB", "MB", "GB", "TB"}
	for i := 0; i < len(units)-1 && v >= 1024; i++ {
		v /= 1024
		if v < 1024 {
			return fmt.Sprintf("%.1f%s", v, units[i+1])
		}
	}
	return fmt.Sprintf("%.0f%s", v, units[0])
}

func humanMbitRate(bytesPerSecond float64) string {
	return fmt.Sprintf("%.2fMbit/s", bytesPerSecond*8/1000/1000)
}

func humanBitRate(bytesPerSecond float64) string {
	bits := bytesPerSecond * 8
	units := []string{"bit/s", "Kbit/s", "Mbit/s", "Gbit/s", "Tbit/s"}
	for i := 0; i < len(units)-1 && bits >= 1000; i++ {
		bits /= 1000
		if bits < 1000 {
			return fmt.Sprintf("%.1f%s", bits, units[i+1])
		}
	}
	return fmt.Sprintf("%.0f%s", bits, units[0])
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	if n <= 3 {
		return s[:n]
	}
	return s[:n-3] + "..."
}
