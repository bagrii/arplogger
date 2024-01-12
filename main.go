package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"os/user"
	"path/filepath"
	"runtime"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"

	"arplogger/internal/arp"
	"arplogger/internal/help"
)

var (
	flagPrint2Log     = flag.Bool("log", false, "Store ARP activity to log file.")
	flagPrint2Console = flag.Bool("console", false, "Print to console.")
	flagLogAll        = flag.Bool("all", false, "Log all ARP activity.")
	flagLogNewPair    = flag.Bool("new", false, "Log only new ARP pairs: IP <-> MAC.")
	flagIntf          = flag.String("interface", "", "Network interface to listen for ARP packets.")
)

func genFilename() (string, error) {
	const layout = "2006-01-02_15.04.05.999999999"
	var root string
	switch runtime.GOOS {
	case "darwin":
		u, _ := user.Current()
		root = filepath.Join(u.HomeDir, "Library", "Logs")
	case "linux":
		root = "/var/log"
	default:
		root = os.TempDir()
	}
	logpath := filepath.Join(root, "arplogger")
	if err := os.MkdirAll(logpath, os.ModePerm); err != nil {
		return "", err
	}
	logFileName := fmt.Sprintf("%s_%s.log", "arplogger", time.Now().Format(layout))
	return filepath.Join(logpath, logFileName), nil
}

func parseFlags() bool {
	flag.Parse()
	if flag.NFlag() == 0 {
		fmt.Print(help.Usage)
		return false
	}
	if !*flagPrint2Console && !*flagPrint2Log {
		fmt.Println("No output is defined. Please, specify -console and/or -log.")
		return false
	}
	if !*flagLogAll && !*flagLogNewPair {
		fmt.Println("No logging mode is defined. Please, specify -all and/or -new")
		return false
	}
	if len(*flagIntf) == 0 {
		fmt.Println("No network interface is specified. " +
			"Please, use -interface to specify source interface to read network packets.")
		return false
	}
	return true
}

func getMode() int {
	var mode int
	if *flagLogAll {
		mode |= arp.LogAllPackets
	}
	if *flagLogNewPair {
		mode |= arp.LogNewPairs
	}
	return mode
}

func getDest() int {
	var dest int
	if *flagPrint2Console {
		dest |= arp.Print2Console
	}
	if *flagPrint2Log {
		dest |= arp.Print2Log
	}
	return dest
}

func getLogFilename(dest *int) string {
	var filename string
	if *dest&arp.Print2Log == arp.Print2Log {
		var err error
		if filename, err = genFilename(); err != nil {
			fmt.Printf("Can't create log file due to error %s. Default printing to console.", err)
			*dest |= arp.Print2Console
		}
	}
	return filename
}

func openInterface(intf string) (*pcap.Handle, error) {
	// max packet size: 64K
	const snaplen = 64*1024 - 1
	handle, err := pcap.OpenLive(intf, snaplen, true, pcap.BlockForever)
	if err != nil {
		return nil, err
	}
	if err := handle.SetBPFFilter("arp"); err != nil {
		return nil, err
	}
	return handle, nil
}

func processPackets(ctx context.Context, handle *pcap.Handle, logger *arp.Logger) {
	src := gopacket.NewPacketSource(handle, layers.LayerTypeEthernet)
	in := src.Packets()
read:
	for {
		var packet gopacket.Packet
		select {
		case <-ctx.Done():
			break read
		case packet = <-in:
			layer := packet.Layer(layers.LayerTypeARP)
			if layer == nil {
				continue
			}
			logger.Log(layer.(*layers.ARP))
		}
	}
}

func main() {
	if !parseFlags() {
		return
	}
	var (
		mode = getMode()
		dest = getDest()
	)
	filename := getLogFilename(&dest)
	logger, err := arp.NewLogger(dest, mode, filename)
	if err != nil {
		fmt.Printf("Failed to create logger due to error: %s.", err)
		return
	}
	defer logger.Close()
	handle, err := openInterface(*flagIntf)
	if err != nil {
		fmt.Printf("Failed to open network interface due to error: %s.", err)
		return
	}
	defer handle.Close()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	if dest&arp.Print2Log == arp.Print2Log {
		fmt.Println("Saving to log file: ", filename)
	}
	fmt.Println("Waiting for incoming ARP packets...")
	processPackets(ctx, handle, logger)
}
