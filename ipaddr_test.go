package ipaddr

import (
	"errors"
	"testing"
)

func TestEqual(t *testing.T) {
	t.SkipNow()
}

func TestIsBroadcast(t *testing.T) {
	t.SkipNow()
}

func TestIsMulticast(t *testing.T) {
	t.SkipNow()
}

func TestNetString(t *testing.T) {
	data := []struct {
		Addr string
		Want string
	}{
		{
			Addr: "192.168.67.236/24",
			Want: "192.168.67.0/24",
		},
	}
	for _, d := range data {
		nw, err := ParseNet(d.Addr)
		if err != nil {
			continue
		}
		got := nw.String()
		if got != d.Want {
			t.Errorf("%s: results mismatched! want %s, got %s", d.Addr, d.Want, got)
		}
	}
}

func TestIPString(t *testing.T) {
	data := []struct {
		Addr string
		Want string
	}{
		{
			Addr: "127.0.0.1",
			Want: "127.0.0.1",
		},
		{
			Addr: "0:0:0:0:0::1",
			Want: "::1",
		},
	}
	for _, d := range data {
		ip, err := ParseIP(d.Addr)
		if err != nil {
			continue
		}
		got := ip.String()
		if got != d.Want {
			t.Errorf("%s: results mismatched! want %s, got %s", d.Addr, d.Want, got)
		}
	}
}

func TestIsLoopback(t *testing.T) {
	data := []struct {
		Addr string
		Want bool
	}{
		{
			Addr: "127.0.0.1",
			Want: true,
		},
		{
			Addr: "::1",
			Want: true,
		},
		{
			Addr: "::",
			Want: false,
		},
		{
			Addr: "192.168.67.181",
			Want: false,
		},
	}
	for _, d := range data {
		ip, err := ParseIP(d.Addr)
		if err != nil {
			t.Errorf("%s: fail to parse %s", d.Addr, err)
			continue
		}
		got := ip.IsLoopback()
		if got != d.Want {
			t.Errorf("%s: results mismatched! want %t, got %t", d.Addr, d.Want, got)
		}
	}
}

func TestParseIP(t *testing.T) {
	data := []struct {
		Addr string
		Err  error
	}{
		{
			Addr: "127.0.0.1",
		},
		{
			Addr: "127.000.000.001",
		},
		{
			Addr: "192.168.67.236",
		},
		{
			Addr: "AAA.001.002.0003",
			Err:  ErrInvalid,
		},
		{
			Addr: "111.257.002.0003",
			Err:  ErrInvalid,
		},
		{
			Addr: "127.0.1",
			Err:  ErrInvalid,
		},
		{
			Addr: "::",
		},
		{
			Addr: "::1",
		},
		{
			Addr: "2001:db8:aaaa:dead:beef:cafe:0:1",
		},
		{
			Addr: "2001:db8::aaaa:0:0:1",
		},
		{
			Addr: "2001:db8:0:0:aaaa::1",
		},
		{
			Addr: "2001:db8:0::1",
		},
		{
			Addr: "2001:db8::1",
		},
		{
			Addr: "2001:db8::",
		},
		{
			Addr: "2001::db8::1",
			Err:  ErrInvalid,
		},
		{
			Addr: "",
			Err:  ErrInvalid,
		},
		{
			Addr: "1.2.3.4.5",
			Err:  ErrInvalid,
		},
		{
			Addr: "1:1",
			Err:  ErrInvalid,
		},
		{
			Addr: "1:2:3:4:5:6:7:8:9",
			Err:  ErrInvalid,
		},
	}
	for _, d := range data {
		_, err := ParseIP(d.Addr)
		if d.Err != nil {
			if err == nil {
				t.Errorf("invalid IP address parse succesfully")
			} else if !errors.Is(err, d.Err) {
				t.Errorf("errors mismatched! want %s, got %s", d.Err, err)
			}
			continue
		}
		if err != nil {
			t.Errorf("%q: unexpected error while parsing: %s", d.Addr, err)
		}
	}
}
