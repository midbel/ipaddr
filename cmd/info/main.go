package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/midbel/ipaddr"
)

const (
	check = "v"
	cross = "x"
	mark  = "?"
)

func main() {
	flag.Parse()

	ip, nw, err := parse(flag.Arg(0))
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fields := []struct {
		Line  string
		Value interface{}
		Only4 bool
    Only6 bool
	}{
		{Line: "address    : %s", Value: ip},
		{Line: "IPv4       : %s", Value: ip.Is4()},
		{Line: "IPv6       : %s", Value: ip.Is6()},
		{Line: "private    : %s", Value: ip.IsPrivate()},
		{Line: "loopback   : %s", Value: ip.IsLoopback()},
		{Line: "multicast  : %s", Value: ip.IsMulticast()},
		{Line: "link-local : %s", Value: ip.IsLinkLocal()},
		{Line: "class      : %s", Value: ip.Class().String(), Only4: true},
		{Line: "network    : %s", Value: nw.Address()},
		{Line: "broadcast  : %s", Value: nw.Broadcast(), Only4: true},
		{Line: "netmask    : %s", Value: nw.Netmask()},
		{Line: "host(s)    : %.0f", Value: nw.Count()},
	}
	for i := range fields {
		if ip.Is6() && fields[i].Only4 {
			continue
		}
		print(fields[i].Line, fields[i].Value)
	}
}

func parse(str string) (ipaddr.IP, ipaddr.Net, error) {
	ip, nw, err := ipaddr.ParseCIDR(str)
	if err != nil {
		ip, err = ipaddr.ParseIP(str)
		if err != nil {
			return ip, nw, err
		}
		nw, _ = ip.Net()
	}
	return ip, nw, nil
}

func print(line string, value interface{}) {
	switch v := value.(type) {
	case bool:
		value = cross
		if v {
			value = check
		}
	case string:
		if value == "" {
			value = mark
		}
	}
	fmt.Printf(line, value)
	fmt.Println()
}
