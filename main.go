package main

import (
	"context"
	"log"

	tea "github.com/charmbracelet/bubbletea"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go visualiser ebpf/visualiser.c

func main() {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	collector, err := newCollector()
	if err != nil {
		log.Fatal(err)
	}
	defer collector.Close()

	program := tea.NewProgram(newModel(), tea.WithAltScreen())
	go func() {
		for msg := range collector.Run(ctx) {
			program.Send(msg)
		}
	}()

	if _, err := program.Run(); err != nil {
		log.Fatal(err)
	}
}
