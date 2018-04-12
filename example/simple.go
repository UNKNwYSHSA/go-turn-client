package main

import (
	"log"
	"time"

	"github.com/f110/go-turn-client"
)

func main() {
	peerClient := turn.Dial("127.0.0.1:3478")
	peerIP, peerPort := peerClient.Allocate()
	peerClient.RefreshAllocation()

	go func() {
		log.Printf("Peer: %s", string(peerClient.Data()))
	}()

	client := turn.Dial("127.0.0.1:3478")
	clientIP, clientPort := client.Allocate()
	_ = clientIP
	_ = clientPort
	client.RefreshAllocation()
	client.CreatePermission(peerIP)
	client.Send(peerIP, peerPort, []byte("test"))

	time.Sleep(1 * time.Second)
}
