package main

import (
	"fmt"
	"log"
	"net"
)

func main() {
	fmt.Println("Starting raw UDP test on 0.0.0.0:53 ...")

	conn, err := net.ListenPacket("udp4", "0.0.0.0:53")
	if err != nil {
		log.Fatalf("FATAL: %v", err)
	}
	defer conn.Close()

	fmt.Println("Listening! Waiting for packets...")

	buf := make([]byte, 4096)
	for {
		n, addr, err := conn.ReadFrom(buf)
		if err != nil {
			log.Printf("ERROR: %v", err)
			continue
		}
		fmt.Printf("GOT PACKET: %d bytes from %s\n", n, addr)
	}
}
