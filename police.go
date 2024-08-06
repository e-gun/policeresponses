package policeresponses

import (
	"fmt"
	"github.com/labstack/echo/v4"
	"net/http"
	"os"
	"strings"
	"time"
)

// QUICKSTART

// e := echo.New()
// e.Use(policeresponses.PoliceRequestAndResponse)
// policeresponses.Emit.ColorOn()
// go policeresponses.ResponseStatsKeeper()
// go policeresponses.IPBlacklistKeeper()
// ...
// e.Logger.Fatal(e.Start(fmt.Sprintf("%s:%d", HostIP, HostPort)))

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

// variables to manage the RESPONSEPOLICING infrastructure
var (
	blistwr = make(chan writeblacklist)
	blistrd = make(chan readblacklist)
	slistwr = make(chan writestats)
	Emit    = func() *Emitter { return &Emitter{E: defaultemit} }()
)

// PoliceRequestAndResponse - track Response code counts + block repeat 404 offenders; this is custom middleware for an *echo.Echo
func PoliceRequestAndResponse(nextechohandler echo.HandlerFunc) echo.HandlerFunc {
	const (
		BLACK0 = `IP address %s was blacklisted: too many previous response code errors\n`
		SLOWDN = 3
		BLACK1 = `IP address %s received a strike: invalid request prefix in URI "%s"\n`
	)

	return func(c echo.Context) error {
		// presumed guilty: 403
		registerresult := writestats{
			code: 403,
			ip:   c.RealIP(),
			uri:  c.Request().RequestURI,
		}

		// already known to be bad?
		checkblacklist := readblacklist{ip: c.RealIP(), resp: make(chan bool)}
		blistrd <- checkblacklist
		ok := <-checkblacklist.resp

		// is something like 'http://journalseek.net/' in the request?
		rq := c.Request().RequestURI
		if strings.HasPrefix(rq, "http:") || strings.HasPrefix(rq, "https:") {
			ok = false
			addtoblacklist := writeblacklist{ip: c.RealIP(), resp: make(chan bool)}
			blistwr <- addtoblacklist
			white := <-addtoblacklist.resp
			if !white {
				fmt.Printf(BLACK1, c.RealIP(), rq)
			}
		}

		if !ok {
			// register a 403
			slistwr <- registerresult
			time.Sleep(SLOWDN * time.Second)
			e := echo.NewHTTPError(http.StatusForbidden, fmt.Sprintf(BLACK0, c.RealIP()))
			return e
		} else {
			// do this before setting c.Response().Status or you will always get "200"
			if err := nextechohandler(c); err != nil {
				c.Error(err)
			}
			// register some other result code
			registerresult.code = c.Response().Status
			slistwr <- registerresult
			return nil
		}
	}
}

// IPBlacklistKeeper - read/write to the blacklist
func IPBlacklistKeeper() {
	const (
		FAILSALLOWED = 3
		BLACK0       = `IP address %s was blacklisted: too many previous Response code errors; %d address(es) on the blacklist`
	)

	strikecount := make(map[string]int)
	blacklist := make(map[string]struct{})

	// NB: this loop will never exit
	// the channels are returning 'bool'
	for {
		select {
		case rd := <-blistrd: // read from the blacklist
			valid := true
			if _, ok := blacklist[rd.ip]; ok {
				// you are on the blacklist...
				valid = false
			}
			rd.resp <- valid
		case wr := <-blistwr: // check strikes; maybe write to the blacklist
			ret := false
			if _, ok := strikecount[wr.ip]; !ok {
				strikecount[wr.ip] = 1
			} else if strikecount[wr.ip] >= FAILSALLOWED {
				blacklist[wr.ip] = struct{}{}
				hl := fmt.Sprintf(Emit.Red+"%s"+Emit.Rst, wr.ip)
				Emit.E(fmt.Sprintf(BLACK0, hl, len(blacklist)))
				ret = true
			} else {
				strikecount[wr.ip]++
			}
			wr.resp <- ret
		}
	}
}

// ResponseStatsKeeper - log echo responses
func ResponseStatsKeeper() {
	const (
		BLACK1 = `IP address %s received a strike: StatusNotFound error for URI "%s"`
		BLACK2 = `IP address %s received a strike: StatusInternalServerError for URI "%s"`
		BLACK3 = `IP address %s received a strike: MethodNotAllowed for URI "%s"`
		FYI200 = `StatusOK count is %d`
		FRQ200 = 1000
		FYI403 = `[%s] StatusForbidden count is %s. Last blocked was %s requesting "%s"`
		FRQ403 = 100
		FYI404 = `[%s] StatusNotFound count is %d`
		FRQ404 = 100
		FYI405 = `[%s] MethodNotAllowed count is %d`
		FRQ405 = 5
		FYI500 = `[%s] StatusInternalServerError count is %d.`
		FRQ500 = 1
	)

	var (
		TwoHundred  = 0
		FourOhThree = 0
		FourOhFour  = 0
		FourOhFive  = 0
		FiveHundred = 0
	)

	warn := func(v int, frq int, fyi string) {
		if v%frq == 0 {
			Emit.E(fmt.Sprintf(fyi, v))
		}
	}

	blacklist := func(status writestats, note string) {
		// you need to be logged on the blacklist...
		wr := writeblacklist{ip: status.ip, resp: make(chan bool)}
		blistwr <- wr
		ok := <-wr.resp
		if !ok {
			hl := fmt.Sprintf(Emit.Yel+"%s"+Emit.Rst, status.ip)
			Emit.E(fmt.Sprintf(BLACK1, hl, status.uri))
		}
	}

	// NB: this loop will never exit
	for {
		status := <-slistwr
		when := time.Now().Format(time.RFC822)
		switch status.code {
		case 200:
			TwoHundred++
			warn(TwoHundred, FRQ200, FYI200)
		case 403:
			// you are already on the blacklist...
			FourOhThree++
			// use of 'when' makes this different...
			if FourOhThree%FRQ403 == 0 {
				hl := fmt.Sprintf(Emit.Yel+"%d"+Emit.Rst, FourOhThree)
				Emit.E(fmt.Sprintf(FYI403, when, hl, status.ip, status.uri))
			}
		case 404:
			FourOhFour++
			warn(FourOhFour, FRQ404, FYI404)
			blacklist(status, BLACK1)
		case 405:
			// these seem to come only from hostile scanners; it is a bug that needs fixing if a real user sees this
			FourOhFive++
			warn(FourOhFive, FRQ405, FYI405)
			blacklist(status, BLACK3)
		case 500:
			FiveHundred++
			warn(FiveHundred, FRQ500, FYI500)
			blacklist(status, BLACK2)
		default:
			// do nothing: not interested
			// 302 from "/reset/session"
			// 101 from "/ws"
		}
	}
}

// Emitter - allows control over how/where the blacklist messages are seen
type Emitter struct {
	E   func(s string)
	Col bool
	Red string
	Yel string
	Rst string
}

func (e *Emitter) ColorOn() {
	e.Red = "\033[38;5;160m" // Red3
	e.Yel = "\033[38;5;143m" // DarkKhaki
	e.Rst = "\033[0m"
}

func (e *Emitter) ColorOff() {
	e.Red = "" // Red3
	e.Yel = "" // DarkKhaki
	e.Rst = ""
}

// defaultemit - just print the line to the terminal
func defaultemit(s string) {
	fmt.Println(s)
}

// emittofile - send output to a file instead; this is just an example, not really for use
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
