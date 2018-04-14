package main

import (
	"log"
	"os"
	"time"

	"github.com/f110/go-turn-client"
)

func main() {
	opt := turn.WithLongTermCredential("1523534350:1", "QpYNHtXvxhSnUZp1Ydd0HlJ7JOk=")
	peerClient := turn.Dial("127.0.0.1:3478", opt)
	peerIP, peerPort, err := peerClient.Allocate()
	if err != nil {
		panic(err)
	}

	go func() {
		log.Printf("Peer: %s", string(peerClient.Read()))
		os.Exit(0)
	}()

	client := turn.Dial("127.0.0.1:3478", opt)
	clientIP, clientPort, err := client.Allocate()
	if err != nil {
		panic(err)
	}
	_ = clientIP
	_ = clientPort
	client.CreatePermission(peerIP)
	client.Send(peerIP, peerPort, []byte("test"))

	time.Sleep(1 * time.Second)
	client.Shutdown()
}
