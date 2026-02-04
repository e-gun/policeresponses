package policeresponses

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/labstack/echo/v5"
)

const (
	// FAILSALLOWED sets the number of bad requests you will accept before assigning someone to the blacklist
	FAILSALLOWED = 5
)

var PoliceRequestAndResponse = PoliceRequestAndResponseV5

// QUICKSTART

// e := echo.New()
// e.Use(policeresponses.PoliceRequestAndResponse)
// policeresponses.Emit.ColorOn()
// go policeresponses.ResponseStatsKeeper()
// go policeresponses.IPBlacklistKeeper()
// ...
// e.Logger.Fatal(e.Start(fmt.Sprintf("%s:%d", HostIP, HostPort)))

// PoliceRequestAndResponseV4 - echo v4; track Response code counts + block repeat 404 offenders; this is custom middleware for an *echo.Echo
//func PoliceRequestAndResponseV4(nextechohandler echo.HandlerFunc) echo.HandlerFunc {
//	const (
//		BLACK0 = "%s blacklisted: too many previous response code errors\n"
//		SLOWDN = 3
//		BLACK1 = "%s: invalid request prefix in URI '%s'\n"
//	)
//
//	return func(c echo.Context) error {
//		// presumed guilty: 403
//		registerresult := writestats{
//			code: 403,
//			ip:   c.RealIP(),
//			uri:  c.Request().RequestURI,
//		}
//
//		// already known to be bad?
//		checkblacklist := readblacklist{ip: c.RealIP(), resp: make(chan bool)}
//		blistrd <- checkblacklist
//		ok := <-checkblacklist.resp
//
//		// is something like 'http://journalseek.net/' in the request?
//		rq := c.Request().RequestURI
//		if strings.HasPrefix(rq, "http:") || strings.HasPrefix(rq, "https:") {
//			ok = false
//			addtoblacklist := writeblacklist{ip: c.RealIP(), resp: make(chan bool)}
//			blistwr <- addtoblacklist
//			white := <-addtoblacklist.resp
//			if !white {
//				fmt.Printf(BLACK1, c.RealIP(), rq)
//			}
//		}
//
//		if !ok {
//			// register a 403
//			slistwr <- registerresult
//			time.Sleep(SLOWDN * time.Second)
//			e := echo.NewHTTPError(http.StatusForbidden, fmt.Sprintf(BLACK0, c.RealIP()))
//			return e
//		} else {
//			// do this before setting c.Response().Status or you will always get "200"
//			if err := nextechohandler(c); err != nil {
//				c.Error(err)
//			}
//			// register some other result code
//			registerresult.code = c.Response().Status
//			slistwr <- registerresult
//			return nil
//		}
//	}
//}

// PoliceRequestAndResponseV5 - echo v5; track Response code counts + block repeat 404 offenders; this is custom middleware for an *echo.Echo
func PoliceRequestAndResponseV5(nextechohandler echo.HandlerFunc) echo.HandlerFunc {
	const (
		BLACK0 = "%s blacklisted: too many previous response code errors\n"
		SLOWDN = 3
		BLACK1 = "%s: invalid request prefix in URI '%s'\n"
	)

	return func(c *echo.Context) error {
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
			var sc echo.HTTPStatusCoder
			status := http.StatusInternalServerError
			err := nextechohandler(c)

			if noerror := errors.As(err, &sc); noerror {
				status = sc.StatusCode()
			} else {
				c.Response().WriteHeader(status)
			}

			// register some other result code
			registerresult.code = status
			slistwr <- registerresult
			return nil
		}
	}
}

// IPBlacklistKeeper - read/write to the blacklist
func IPBlacklistKeeper() {
	const (
		BLACK0 = "%s blacklisted: too many errors; blacklist count now %d\n"
	)

	strikecount := make(map[string]int)
	blacklist := make(map[string]struct{})
	whitelist := make(map[string]struct{})

	for _, w := range AlwaysWhite {
		whitelist[w] = struct{}{}
	}

	for _, b := range StartBlack {
		blacklist[b] = struct{}{}
	}

	// NB: this loop will never exit
	// the channels are returning 'bool'
	for {
		select {
		case rd := <-blistrd: // read from the blacklist
			valid := true
			if _, w := whitelist[rd.ip]; w {
				// stop checking
			} else if _, ok := blacklist[rd.ip]; ok {
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
		BLACK1 = "%s: StatusNotFound error for URI '%s'\n"
		BLACK2 = "%s: StatusInternalServerError for URI '%s'\n"
		BLACK3 = "%s: MethodNotAllowed for URI '%s'\n"
		FYI200 = "StatusOK count is %s\n"
		FYI403 = "StatusForbidden count is %s. Last blocked was %s requesting '%s'\n"
		FYI404 = "StatusNotFound count is %s\n"
		FYI405 = "MethodNotAllowed count is %s\n"
		FYI500 = "StatusInternalServerError count is %s\n"
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
			hl := fmt.Sprintf(Emit.Yel+"%d"+Emit.Rst, v)
			Emit.E(fmt.Sprintf(fyi, hl))
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
		// when := time.Now().Format(time.RFC822)
		switch status.code {
		case 200:
			TwoHundred++
			warn(TwoHundred, NF.FRQ200, FYI200)
		case 403:
			// you are already on the blacklist...
			FourOhThree++
			// use of 'when' makes this different...
			if FourOhThree%NF.FRQ403 == 0 {
				hl := fmt.Sprintf(Emit.Yel+"%d"+Emit.Rst, FourOhThree)
				Emit.E(fmt.Sprintf(FYI403, hl, status.ip, status.uri))
			}
		case 404:
			FourOhFour++
			warn(FourOhFour, NF.FRQ404, FYI404)
			blacklist(status, BLACK1)
		case 405:
			// these seem to come only from hostile scanners; it is a bug that needs fixing if a real user sees this
			FourOhFive++
			warn(FourOhFive, NF.FRQ405, FYI405)
			blacklist(status, BLACK3)
		case 500:
			FiveHundred++
			warn(FiveHundred, NF.FRQ500, FYI500)
			blacklist(status, BLACK2)
		default:
			// do nothing: not interested
			// 302 is uninteresting
			// 101 from websocket is uninteresting
			// ...
		}
	}
}
