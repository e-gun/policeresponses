# policeresponses

track http response code counts + block repeat 404 offenders; this is custom middleware for an `*echo.Echo` but not much effort would be required to make it work for a `mux := http.NewServeMux()` environment

cf `fail2ban`

```
QUICKSTART

e := echo.New()
e.Use(policeresponses.PoliceRequestAndResponse)
policeresponses.Emit.ColorOn()
go policeresponses.ResponseStatsKeeper()
go policeresponses.IPBlacklistKeeper()
...
e.Logger.Fatal(e.Start(fmt.Sprintf("%s:%d", HostIP, HostPort)))

```

```
THINGS TO TOGGLE (in 'support.go')

[a] policeresponses.Emit

emit to a file? to screen? in color?

[b] policeresponses.NF

how often do you want updates on 404s, etc?

```