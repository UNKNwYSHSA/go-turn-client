package main

import (
	"github.com/f110/go-turn-client"
)

func main() {
	c := turn.Dial("127.0.0.1:3478")
	c.Allocate()
	c.ChannelBind(24032)
}
