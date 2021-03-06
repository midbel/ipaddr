package main

import (
	"flag"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/midbel/fig"
	"github.com/midbel/ipaddr"
)

func main() {
	var (
		print = flag.Bool("p", false, "print route tables")
		check = flag.Bool("c", false, "check routes with list of routers")
		graph = flag.Bool("g", false, "print graph")
	)
	flag.Parse()

	topo, err := Load(flag.Arg(0))
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	switch {
	case *print:
		printTables(topo)
	case *check:
		checkRoutes(topo, flag.Args())
	case *graph:
		printGraph(topo)
	}
}

const arrow = "\u279C"

func printGraph(topo Topology) {
	n := buildGraph(topo)
	for _, n := range n.Nodes {
		printNode(n, 0)
	}
}

const step = 2

func printNode(n Node, level int) {
	prefix := strings.Repeat(" ", level)
	fmt.Print(prefix)
	fmt.Printf("%s ", n.Router.Id)
	if !n.Via.Net.IsZero() {
		fmt.Printf("(%s %s %s) [", n.Router.Addr, arrow, n.Via.Net)
	} else {
		fmt.Printf("(%s) [", n.Router.Addr)
	}
	fmt.Println()
	for _, n := range n.Nodes {
		printNode(n, level+step)
	}
	if len(n.Nodes) == 0 {
		fmt.Printf("%s<empty>", strings.Repeat(" ", level+step+1))
		fmt.Println()
	}
	fmt.Printf("%s]", prefix)
	fmt.Println()
}

const line = " %-16s | %-16s | %-16s | %6s | %4d | %s"

func printTables(topo Topology) {
	printRoutes(topo.Routes)
	if len(topo.Routers) == 0 {
		return
	}
	for _, r := range topo.Routers {
		if len(r.Routes) == 0 {
			continue
		}
		fmt.Println()
		fmt.Printf("%s (%s)", r.Id, r.Addr)
		fmt.Println()
		printRoutes(r.Routes)
	}
}

func printRoutes(rs []Route) {
	for _, r := range rs {
		fmt.Printf(line, r.NetAddr.Address(), r.NetAddr.Netmask(), r.Gateway, r.Iface, r.Metric, r.State.String())
		fmt.Println()
	}
}

func checkRoutes(topo Topology, args []string) {
	if z := len(args[1:]); z > 0 {
		as := make([]Addr, 0, z)
		for i := range args[1:] {
			ip, _, err := ipaddr.ParseCIDR(args[i+1])
			if err == nil {
				as = append(as, Addr{ip})
			}
		}
		topo.Addrs = append(topo.Addrs, as...)
	}
	for _, a := range topo.Addrs {
		r, err := topo.BestRoute(a.IP)
		if err != nil {
			fmt.Println(err)
			continue
		}
		hops, err := next(a.IP, r, topo.Routers)
		if err != nil {
			fmt.Println(err)
			continue
		}
		printHops(append(hops, a.IP))
	}
}

func printHops(list []ipaddr.IP) {
	fmt.Printf("%2d hop(s): ", len(list)-1)
	for i := range list {
		if i > 0 {
			fmt.Printf(" %s ", arrow)
		}
		fmt.Print(list[i])
	}
	fmt.Println()
}

func next(ip ipaddr.IP, route Route, routers []Router) ([]ipaddr.IP, error) {
	var list []ipaddr.IP
	for {
		if hasLoop(route.Gateway.IP, list) {
			return nil, fmt.Errorf("%s: loop detected", route.Gateway.IP)
		}
		list = append(list, route.Gateway.IP)
		r, err := findRouter(route.Gateway, routers)
		if err != nil {
			return nil, err
		}
		if r.IsHost() || r.IsEmpty() {
			break
		}
		route, err = r.BestRoute(ip)
		if err != nil {
			return nil, err
		}
	}
	return list, nil
}

func hasLoop(ip ipaddr.IP, list []ipaddr.IP) bool {
	for i := range list {
		if list[i].Equal(ip) {
			return true
		}
	}
	return false
}

type Addr struct {
	ipaddr.IP
}

func (a *Addr) Equal(other Addr) bool {
	return a.IP.Equal(other.IP)
}

func (a *Addr) Less(other Addr) bool {
	return a.IP.Less(other.IP)
}

func (a *Addr) Set(v interface{}) error {
	str, ok := v.(string)
	if !ok {
		return fmt.Errorf("%v: string expected (got %[1]T)", v)
	}
	ip, err := ipaddr.ParseIP(str)
	if err == nil {
		a.IP = ip
	}
	return err
}

type Status byte

const (
	Up Status = iota << 1
	Down
)

func (s *Status) String() string {
	switch *s {
	case Up:
		return "U"
	case Down:
		return "D"
	default:
		return "?"
	}
}

func (s *Status) Set(v interface{}) error {
	str, ok := v.(string)
	if !ok {
		return fmt.Errorf("%v: string expected (got %[1]T)", v)
	}
	switch str {
	case "U":
		*s = Up
	case "D", "":
		*s = Down
	default:
		return fmt.Errorf("%s: unknown status", str)
	}
	return nil
}

func (s *Status) Up() bool {
	return *s == Up
}

type Net struct {
	ipaddr.Net
}

func (n *Net) Less(other Net) bool {
	return n.Net.Less(other.Net)
}

func (n *Net) Equal(other Net) bool {
	return n.Net.Equal(other.Net)
}

func (n *Net) Set(v interface{}) error {
	str, ok := v.(string)
	if !ok {
		return fmt.Errorf("%v: string expected (got %[1]T)", v)
	}
	_, nw, err := ipaddr.ParseCIDR(str)
	if err != nil {
		ip, _ := ipaddr.ParseIP(str)
		nw, err = ip.Net()
	}
	if err == nil {
		n.Net = nw
	}
	return err
}

type Route struct {
	NetAddr Net    `fig:"network"`
	Gateway Addr   `fig:"gateway"`
	Iface   string `fig:"iface"`
	State   Status
	Metric  int
}

func (r Route) Match(ip ipaddr.IP) bool {
	if !r.State.Up() {
		return false
	}
	return r.NetAddr.Contains(ip) || r.NetAddr.IsZero()
}

type Type byte

const (
	TypeHost = iota + 1
	TypeRouter
	TypeSwitch
	TypeFirewall
)

func (t *Type) Set(v interface{}) error {
	str, ok := v.(string)
	if !ok {
		return fmt.Errorf("%v: string expected (got %[1]T)", v)
	}
	switch str {
	case "", "host":
		*t = TypeHost
	case "fw", "firewall":
		*t = TypeFirewall
	case "switch":
		*t = TypeSwitch
	case "router":
		*t = TypeRouter
	default:
	}
	return nil
}

func (t *Type) String() string {
	return ""
}

type Router struct {
	Id     string `fig:"id"`
	Type   Type
	Addr   Addr    `fig:"ip"`
	Routes []Route `fig:"route"`
}

func (r Router) IsHost() bool {
	return len(r.Routes) == 0 || r.Type == TypeHost
}

func (r Router) IsEmpty() bool {
	return len(r.Routes) == 0
}

func (r Router) BestRoute(ip ipaddr.IP) (Route, error) {
	return bestRoute(ip, r.Routes)
}

type Topology struct {
	Addrs   []Addr   `fig:"addr"`
	Routes  []Route  `fig:"route"`
	Routers []Router `fig:"device"`
}

func Load(file string) (topo Topology, err error) {
	r, err := os.Open(file)
	if err != nil {
		return topo, err
	}
	defer r.Close()

	if err := fig.Decode(r, &topo); err != nil {
		return topo, err
	}
	topo.Routes = sortRoutes(topo.Routes)
	sort.Slice(topo.Routers, func(i, j int) bool {
		return !topo.Routers[i].Addr.Less(topo.Routers[j].Addr)
	})
	for _, r := range topo.Routers {
		r.Routes = sortRoutes(r.Routes)
	}
	return topo, nil
}

func (t Topology) BestRoute(ip ipaddr.IP) (Route, error) {
	return bestRoute(ip, t.Routes)
}

func findRouter(ip Addr, routers []Router) (Router, error) {
	i := sort.Search(len(routers), func(i int) bool {
		return routers[i].Addr.Less(ip) || routers[i].Addr.Equal(ip)
	})
	if i < len(routers) && routers[i].Addr.Equal(ip) {
		return routers[i], nil
	}
	return Router{}, fmt.Errorf("%s: router not found!", ip)
}

func bestRoute(ip ipaddr.IP, routes []Route) (Route, error) {
	for _, r := range routes {
		if r.Match(ip) {
			return r, nil
		}
	}
	nw, _ := ip.Net()
	return Route{}, fmt.Errorf("%s: network unreachable", nw)
}

func sortRoutes(routes []Route) []Route {
	sort.Slice(routes, func(i, j int) bool {
		return routes[i].NetAddr.Less(routes[j].NetAddr)
	})
	return routes
}

type Node struct {
	Router
	MaxDepth int
	Depth    int
	Cost     int
	Via      Net
	State    Status
	Nodes    []Node
}

func buildGraph(topo Topology) Node {
	var (
		n  Node
		rs = make([]Router, len(topo.Routers))
	)
	copy(rs, topo.Routers)
	sort.Slice(rs, func(i, j int) bool {
		return len(rs[i].Routes) > len(rs[j].Routes)
	})
	for _, r := range rs {
		c := Node{
			Router: r,
			Depth:  1,
		}
		c.Nodes, c.MaxDepth = buildNode(r, topo.Routers, c.Depth+1)
		c.MaxDepth++
		if n.MaxDepth == 0 || c.MaxDepth > n.MaxDepth {
			n.MaxDepth = c.MaxDepth
		}
		n.Nodes = append(n.Nodes, c)
	}
	return n
}

func buildNode(r Router, routers []Router, level int) ([]Node, int) {
	var (
		ns []Node
		dp int
	)
	if len(r.Routes) == 0 {
		return ns, 0
	}
	for _, r := range r.Routes {
		rs, err := findRouter(r.Gateway, routers)
		if err != nil {
			continue
		}
		n := Node{
			Router: rs,
			Depth:  level,
			Via:    r.NetAddr,
		}
		n.Nodes, n.MaxDepth = buildNode(rs, routers, level+1)
		n.MaxDepth++
		if dp == 0 || n.MaxDepth > dp {
			dp = n.MaxDepth
		}
		ns = append(ns, n)
	}
	return ns, dp
}
