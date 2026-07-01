package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

type rawConnectionEvent struct {
	SrcIP   uint32
	DstIP   uint32
	SrcPort uint16
	DstPort uint16
	Comm    [16]byte
}

type connectionEvent struct {
	Time    time.Time
	Process string
	SrcIP   string
	SrcPort uint16
	DstIP   string
	DstPort uint16
}

type connectionMsg connectionEvent

type collectorErrMsg struct {
	err error
}

type collector struct {
	objs   visualiserObjects
	link   link.Link
	reader *ringbuf.Reader
	once   sync.Once
}

func newCollector() (*collector, error) {
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, err
	}

	c := &collector{}
	if err := loadVisualiserObjects(&c.objs, nil); err != nil {
		return nil, err
	}

	attached, err := link.AttachTracing(link.TracingOptions{
		Program: c.objs.TcpConnect,
	})
	if err != nil {
		c.objs.Close()
		return nil, err
	}
	c.link = attached

	rd, err := ringbuf.NewReader(c.objs.ConnEvents)
	if err != nil {
		c.link.Close()
		c.objs.Close()
		return nil, err
	}
	c.reader = rd

	return c, nil
}

func (c *collector) Run(ctx context.Context) <-chan teaMsg {
	out := make(chan teaMsg)

	go func() {
		<-ctx.Done()
		c.Close()
	}()

	go func() {
		defer close(out)
		for {
			record, err := c.reader.Read()
			if err != nil {
				if !errors.Is(err, ringbuf.ErrClosed) {
					out <- collectorErrMsg{err: fmt.Errorf("reading ring buffer: %w", err)}
				}
				return
			}

			event, err := decodeConnection(record.RawSample)
			if err != nil {
				out <- collectorErrMsg{err: fmt.Errorf("decoding event: %w", err)}
				continue
			}
			out <- connectionMsg(event)
		}
	}()

	return out
}

func (c *collector) Close() {
	c.once.Do(func() {
		if c.reader != nil {
			c.reader.Close()
		}
		if c.link != nil {
			c.link.Close()
		}
		c.objs.Close()
	})
}

func decodeConnection(sample []byte) (connectionEvent, error) {
	var raw rawConnectionEvent
	if err := binary.Read(bytes.NewReader(sample), binary.NativeEndian, &raw); err != nil {
		return connectionEvent{}, err
	}

	return connectionEvent{
		Time:    time.Now(),
		Process: string(bytes.TrimRight(raw.Comm[:], "\x00")),
		SrcIP:   intToIP(raw.SrcIP, binary.NativeEndian),
		SrcPort: raw.SrcPort,
		DstIP:   intToIP(raw.DstIP, binary.NativeEndian),
		DstPort: raw.DstPort,
	}, nil
}

func intToIP(ip uint32, order binary.ByteOrder) string {
	b := make(net.IP, 4)
	order.PutUint32(b, ip)
	return b.String()
}
