package main

import (
	"fmt"
	"net"
)

func main() {
	ifaces, err := net.Interfaces()
	if err != nil {
		panic(err)
	}

	var recommended *net.Interface

	fmt.Println("I.Interfaces:")
	for _, iface := range ifaces {
		addrs, _ := iface.Addrs()
		fmt.Printf("- %s (MTU: %d, Flags: %s)\n", iface.Name, iface.MTU, iface.Flags)
		for _, addr := range addrs {
			fmt.Printf("  IP: %s\n", addr.String())
		}

		if recommended == nil && (iface.Flags&net.FlagUp != 0) && (iface.Flags&net.FlagLoopback == 0) && len(addrs) > 0 {
			recommended = &iface
		}
	}

	if recommended != nil {
		fmt.Printf("\nRecomended interface: %s\n", recommended.Name)
	} else {
		fmt.Println("\nNo interfaces found. Better install pcap")
	}
}
