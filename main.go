package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go visualiser ebpf/visualiser.c

type ConnectionEvent struct {
	SrcIP   uint32
	DstIP   uint32
	SrcPort uint16
	DstPort uint16
	Char    [16]byte
}

func main() {
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}

	obj := visualiserObjects{}
	err := loadVisualiserObjects(&obj, nil)
	if err != nil {
		log.Fatal(err)
	}
	defer obj.Close()
	l, err := link.AttachTracing(link.TracingOptions{
		Program: obj.TcpConnect,
	})
	if err != nil {
		log.Fatal(err)
	}
	defer l.Close()
	rd, err := ringbuf.NewReader(obj.ConnEvents)
	if err != nil {
		log.Fatal(err)
	}
	defer rd.Close()

	fmt.Println("Watching outbound connections...")
	fmt.Printf("%-20s %-20s %-6s %-6s %-16s\n", "SRC IP", "DST IP", "SPORT", "DPORT", "PROCESS")
	// watching out for a ctrl+c to cancel
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sig
		rd.Close()
	}()
	for {
		record, err := rd.Read()
		if err != nil {
			if !errors.Is(err, ringbuf.ErrClosed) {
				log.Printf("reading ring buffer: %v", err)
			}
			break
		}
		var event ConnectionEvent
		err = binary.Read(bytes.NewReader(record.RawSample), binary.NativeEndian, &event)
		if err != nil {
			log.Printf("decoding event: %v", err)
			continue
		}
		srcIP := intToIP(event.SrcIP, binary.NativeEndian)
		dstIP := intToIP(event.DstIP, binary.NativeEndian)
		comm := string(bytes.TrimRight(event.Char[:], "\x00"))

		fmt.Printf("%-20s %-20s %-6d %-6d %-16s\n",
			srcIP, dstIP, event.SrcPort, event.DstPort, comm)

	}

}

func intToIP(ip uint32, order binary.ByteOrder) string {
	b := make(net.IP, 4)
	order.PutUint32(b, ip)
	return b.String()
}
