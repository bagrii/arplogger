package arp

import (
	"errors"
	"io"
	"log"
	"net"
	"net/netip"
	"os"
	"slices"
	"strings"

	"github.com/google/gopacket/layers"
)

const (
	// Print2Log stores ARP packets logs to log file in a system predefined paths:
	// macOS: ~/Library/Logs/arplogger
	// Linux: /var/log/arplogger
	// Others: system temporary dir
	Print2Log = iota + 1
	// Print2Console print logs to console.
	Print2Console
)

const (
	// LogAllPackets stores all incoming packets information to log file.
	LogAllPackets = iota + 1
	// LogNewPairs keeps track of new pair of IP <-> MAC and stores only new pairs to log file.
	LogNewPairs
)

const logWarningPrefix = "[WARNING] "
const logChangeMappingPrefix = "[CHANGE MAPPING] "
const logNewMappingPrefix = "[NEW MAPPING] "

type ipv4 [4]byte

type Logger struct {
	logger   *log.Logger
	mode     int
	arptable map[ipv4]net.HardwareAddr
}

// Log extract packet sender IP/MAC addresses and looking into local ARP table to log the following conditions:
// - This is the new mapping of IP <-> MAC, not visible before.
// - The existing mapping of IP <-> MAC has been changed.
func (l *Logger) Log(layer *layers.ARP) {
	if layer.HwAddressSize != 6 {
		l.logger.Printf(logWarningPrefix+"Packet MAC address size is not correct: %d, but should be 6 bytes",
			layer.HwAddressSize)
		return
	}
	if layer.ProtAddressSize != 4 {
		l.logger.Printf(logWarningPrefix+"Packet IPv4 address size is not correct: %d, but should be 4 bytes",
			layer.ProtAddressSize)
		return
	}
	if l.mode&LogAllPackets == LogAllPackets {
		l.logger.Println(prettyPrint(layer))
	}
	ipaddr := ipv4(layer.SourceProtAddress)
	hwaddr := net.HardwareAddr(layer.SourceHwAddress)
	if addr, ok := l.arptable[ipaddr]; ok {
		if slices.Equal(hwaddr, addr) {
			// already in a ARP table, no need to check
			return
		}
		for k, v := range l.arptable {
			if slices.Equal(hwaddr, v) {
				delete(l.arptable, k)
				break
			}
		}
		naddr := netip.AddrFrom4(ipaddr)
		if l.mode&LogNewPairs == LogNewPairs {
			l.logger.Printf(logChangeMappingPrefix+"Previous mapping: %s <-> %s, new mapping: %s <-> %s",
				naddr, l.arptable[ipaddr], naddr, hwaddr)
		}
		l.arptable[ipaddr] = hwaddr
	} else {
		var found bool
		for k, v := range l.arptable {
			found = slices.Equal(hwaddr, v)
			if found {
				if l.mode&LogNewPairs == LogNewPairs {
					l.logger.Printf(logChangeMappingPrefix+"Previous mapping: %s <-> %s, new mapping: %s <-> %s",
						netip.AddrFrom4(k), hwaddr, netip.AddrFrom4(ipaddr), hwaddr)
				}
				delete(l.arptable, k)
				l.arptable[ipaddr] = hwaddr
				break
			}
		}
		if !found {
			if l.mode&LogNewPairs == LogNewPairs {
				l.logger.Printf(logNewMappingPrefix+"%s <-> %s", netip.AddrFrom4(ipaddr), hwaddr)
			}
			l.arptable[ipaddr] = hwaddr
		}
	}
}

func (l *Logger) Close() error {
	if logFile, ok := l.logger.Writer().(*os.File); ok {
		if err := logFile.Sync(); err != nil {
			return err
		}
		if err := logFile.Close(); err != nil {
			return err
		}
	}
	return nil
}

// NewLogger returns new ARP packet logger with specified logging destination (console or file)
// and logging mode (all packets or only new pairs of IP <-> MAC)
func NewLogger(dest, mode int, filename string) (*Logger, error) {
	if dest == 0 || mode == 0 {
		return nil, errors.New("dest and mode arguments should be specified")
	}
	writers := make([]io.Writer, 0, 2)
	if dest&Print2Log == Print2Log {
		logFile, err := os.OpenFile(filename, os.O_CREATE|os.O_RDWR, 0666)
		if err != nil {
			return nil, err
		}
		writers = append(writers, logFile)
	}
	if dest&Print2Console == Print2Console {
		writers = append(writers, os.Stdout)
	}
	logger := log.New(io.MultiWriter(writers...), "", log.LstdFlags)
	return &Logger{logger: logger, mode: mode,
		arptable: make(map[ipv4]net.HardwareAddr)}, nil
}

func prettyPrint(layer *layers.ARP) string {
	var sb strings.Builder
	var op string
	switch layer.Operation {
	case layers.ARPRequest:
		op = "Request"
	case layers.ARPReply:
		op = "Reply"
	}
	sb.WriteString("Operation: " + op)
	sb.WriteString(", Source MAC: " + net.HardwareAddr(layer.SourceHwAddress).String())
	sb.WriteString(", Source IP: " + netip.AddrFrom4([4]byte(layer.SourceProtAddress)).String())
	sb.WriteString(", Destination MAC: " + net.HardwareAddr(layer.DstHwAddress).String())
	sb.WriteString(", Destination IP: " + netip.AddrFrom4([4]byte(layer.DstProtAddress)).String())
	return sb.String()
}
