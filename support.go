package policeresponses

import (
	"fmt"
	"os"
	"time"
)

//
// vars
//

var (
	blistwr = make(chan writeblacklist)
	blistrd = make(chan readblacklist)
	slistwr = make(chan writestats)

	// Emit - how the messages are going to reach you
	Emit = func() *Emitter { return &Emitter{E: defaultemit} }()

	// NF - defaults for notification frequency
	NF = func() *notiffrq {
		return &notiffrq{
			FRQ200: 1000,
			FRQ403: 100,
			FRQ404: 100,
			FRQ405: 5,
			FRQ500: 1,
		}
	}()
)

//
// structs
//

type readblacklist struct {
	ip   string
	resp chan bool
}

type writeblacklist struct {
	ip   string
	resp chan bool
}

type writestats struct {
	code int
	ip   string
	uri  string
}

// notiffrq - how often to notify per response code
type notiffrq struct {
	FRQ200 int
	FRQ403 int
	FRQ404 int
	FRQ405 int
	FRQ500 int
}

//
// emitter
//

// Emitter - allows control over how/where the blacklist messages are seen
type Emitter struct {
	E   func(s string)
	Col bool
	Red string
	Yel string
	Rst string
}

// ColorOn - enable ansi escape color codes
func (e *Emitter) ColorOn() {
	e.Red = "\033[38;5;160m" // Red3
	e.Yel = "\033[38;5;143m" // DarkKhaki
	e.Rst = "\033[0m"
}

// ColorOff - disable ansi escape color codes
func (e *Emitter) ColorOff() {
	e.Red = ""
	e.Yel = ""
	e.Rst = ""
}

// defaultemit - just print the line to the terminal
func defaultemit(s string) {
	fmt.Println(s)
}

// emittofile - send output to a file instead; this is just an example; you will want a different filename
func emittofile(s string) {
	var (
		EFile  = "policeresponses-log.txt"
		MyName = "policeresponses"
	)
	tn := time.Now().Format(time.RFC3339)
	ms := fmt.Sprintf("[%s] [%s] %s\n", tn, MyName, s)
	f, err := os.OpenFile(EFile, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0600)
	if err != nil {
		panic(err)
	}
	defer f.Close()
	if _, err = f.WriteString(ms); err != nil {
		panic(err)
	}
	return
}
