package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"

	tea "github.com/charmbracelet/bubbletea"
)

var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

func main() {
	iface := flag.String("i", "all", "network interface to capture, or all")
	modeFlag := flag.String("mode", string(modeHost), "capture mode: host or gateway")
	list := flag.Bool("list", false, "list capture interfaces")
	showVersion := flag.Bool("version", false, "print version and exit")
	flag.Parse()

	if *showVersion {
		fmt.Printf("net-peek %s (%s, %s)\n", version, commit, date)
		return
	}

	if *list {
		names, err := availableInterfaces()
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		fmt.Println(names)
		return
	}

	mode := captureMode(*modeFlag)
	switch mode {
	case modeHost, modeGateway:
	default:
		fmt.Fprintf(os.Stderr, "unknown mode %q; expected host or gateway\n", *modeFlag)
		os.Exit(1)
	}

	capture, err := newCaptureManagerWithMode(context.Background(), *iface, mode)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	defer capture.stop()

	p := tea.NewProgram(newModel(capture, *iface, mode), tea.WithAltScreen())
	if _, err := p.Run(); err != nil {
		log.Fatal(err)
	}
}
