package ipaddr

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"math/bits"
	"net"
	"strconv"
	"strings"
)

var ErrInvalid = errors.New("invalid IP address")

const (
	netmask4   = 4
	netmask8   = 8
	netmask10  = 10
	netmask16  = 16
	netmask24  = 24
	netmask32  = 32
	netmask64  = 64
	netmask128 = 128
)

type Class string

func (c Class) String() string {
	switch c {
	default:
		return ""
	case ClassA:
		return string(ClassA)
	case ClassB:
		return string(ClassB)
	case ClassC:
		return string(ClassC)
	case ClassD:
		return string(ClassD)
	case ClassE:
		return string(ClassE)
	}
}

func (c Class) Contains(ip IP) bool {
	if ip.zone != z4 {
		return false
	}
	return c == ip.Class()
}

const (
	ClassA Class = "A"
	ClassB       = "B"
	ClassC       = "C"
	ClassD       = "D"
	ClassE       = "E"
)

type zone int8

const (
	z4 zone = -(iota + 1)
	z6
)

func (z zone) String() string {
	switch z {
	case z4:
		return "v4"
	case z6:
		return "v6"
	default:
		return ""
	}
}

type IP struct {
	set  bitset
	mask uint8
	zone
}

var Zero IP

func ParseIP(str string) (IP, error) {
	if strings.Index(str, ".") > 0 {
		return parseIPv4(str)
	}
	if strings.Index(str, ":") >= 0 {
		return parseIPv6(str)
	}
	return Zero, ErrInvalid
}

func ParseCIDR(str string) (IP, Net, error) {
	var (
		x   = strings.Index(str, "/")
		ip  IP
		nw  Net
		err error
	)
	if x <= 0 {
		return ip, nw, ErrInvalid
	}
	if ip, err = ParseIP(str[:x]); err != nil {
		return ip, nw, err
	}
	mask, err := strconv.ParseUint(str[x+1:], 10, 8)
	if err != nil {
		return ip, nw, ErrInvalid
	}
	ip.mask = uint8(mask)
	nw, err = ip.Mask(ip.mask)
	return ip, nw, err
}

func FromStdIP(ip net.IP) (IP, error) {
	if len(ip) == net.IPv4len {
		return IPv4(ip[0], ip[1], ip[2], ip[3]), nil
	}
	if len(ip) == net.IPv6len {
		if allBytes(ip[:10], 0x0) && allBytes(ip[10:12], 0xFF) {
			return IPv4(ip[12], ip[13], ip[14], ip[15]), nil
		}
		var (
			a = binary.BigEndian.Uint16(ip[0:])
			b = binary.BigEndian.Uint16(ip[2:])
			c = binary.BigEndian.Uint16(ip[4:])
			d = binary.BigEndian.Uint16(ip[6:])
			e = binary.BigEndian.Uint16(ip[8:])
			f = binary.BigEndian.Uint16(ip[10:])
			g = binary.BigEndian.Uint16(ip[12:])
			h = binary.BigEndian.Uint16(ip[14:])
		)
		return IPv6(a, b, c, d, e, f, g, h), nil
	}
	return IP{}, fmt.Errorf("invalid number of bytes in %s", ip)
}

func IPv4(a, b, c, d uint8) IP {
	return makeIP(set4(a, b, c, d), z4)
}

func IPv6(a, b, c, d, e, f, g, h uint16) IP {
	return makeIP(set8(a, b, c, d, e, f, g, h), z6)
}

func (i IP) String() string {
	if i.zone == 0 {
		return ""
	}
	if i.zone == z4 {
		return formatIPv4(i)
	}
	return formatIPv6(i)
}

func (i IP) Equal(other IP) bool {
	return i.zone == other.zone && i.set.equal(other.set)
}

func (i IP) Less(other IP) bool {
	if i.zone < other.zone {
		return true
	}
	return i.set.less(other.set)
}

func (i IP) Is4() bool {
	return i.zone == z4
}

func (i IP) Is6() bool {
	return i.zone == z6
}

func (i IP) Mask(mask uint8) (Net, error) {
	limit := netmask32
	if i.zone == z6 {
		limit = netmask128
	}
	set, err := setbits(uint64(mask), uint64(limit))
	if err != nil {
		return Net{}, err
	}
	n := Net{
		ip:   makeIP(set.and(i.set), i.zone),
		mask: set,
	}
	return n, nil
}

func (i IP) Net() (Net, error) {
	m := i.mask
	if m == 0 {
		m = uint8(i.DefaultMask())
	}
	return i.Mask(m)
}

func (i IP) DefaultMask() int {
	if i.zone == 0 {
		return 0
	}
	if i.zone == z4 {
		return defaultNetmaskIPv4(i)
	}
	return defaultNetmaskIPv6(i)

}

func (i IP) IsLoopback() bool {
	if i.zone == 0 {
		return false
	}
	if i.zone == z4 {
		return byte(i.set.low>>24) == 127
	}
	return i.set.high == 0 && i.set.low == 1
}

func (i IP) IsMulticast() bool {
	if i.zone == 0 {
		return false
	}
	if i.zone == z4 {
		return byte(i.set.low>>4) == 0b1110
	}
	return byte(i.set.high>>56) == 0b1111_1111
}

func (i IP) IsUndefined() bool {
	return i.set.isZero()
}

func (i IP) IsPrivate() bool {
	if i.zone == 0 {
		return false
	}
	if i.zone == z6 {
		prefix := i.set.high >> 56
		return prefix == 0xfd || prefix == 0xfc
	}
	var (
		fst = byte(i.set.low >> 24)
		snd = byte(i.set.low >> 16)
	)
	switch {
	case fst == 10:
	case fst == 172 && snd == 16:
	case fst == 192 && snd == 168:
	default:
		return false
	}
	return true
}

func (i IP) IsLinkLocal() bool {
	if i.zone == 0 {
		return false
	}
	if i.zone == z4 {
		fst, snd := byte(i.set.low>>24), byte(i.set.low>>16)
		return fst == 169 && snd == 254
	}
	return uint16(i.set.high>>54) == 0b1111_1110_10
}

func (i IP) Class() Class {
	if i.zone != z4 {
		return ""
	}
	var k Class
	switch high := byte(i.set.low >> 24); {
	case high>>7 == 0:
		k = ClassA
	case high>>6 == 0b10:
		k = ClassB
	case high>>5 == 0b110:
		k = ClassC
	case high>>4 == 0b1110:
		k = ClassD
	case high>>4 == 0b1111:
		k = ClassE
	}
	return k
}

func (i IP) ToStdIP() net.IP {
	ip := make(net.IP, net.IPv6len)
	i.set.copy(ip)
	return ip
}

type Net struct {
	ip   IP
	mask bitset
}

func ParseNet(str string) (Net, error) {
	_, nw, err := ParseCIDR(str)
	return nw, err
}

func (n Net) Contains(ip IP) bool {
	set := n.mask.and(ip.set)
	return set.equal(n.ip.set)
}

func (n Net) Less(other Net) bool {
	less := n.mask.zeros() > other.mask.zeros()
	if !less {
		less = n.ip.Less(other.ip)
	}
	return less
}

func (n Net) IsZero() bool {
	return n.ip.set.isZero() && n.mask.isZero()
}

func (n Net) Count() float64 {
	if n.ip.zone == 0 {
		return 0
	}
	if n.ip.zone == z4 {
		return countHostsNetv4(n.mask)
	}
	return countHostsNetv6(n.mask)
}

func (n Net) Broadcast() IP {
	if n.ip.zone != z4 || n.Count() == 1 {
		return Zero
	}
	n.ip.set.low |= (1 << n.mask.zeros()) - 1
	return n.ip
}

func (n Net) Address() IP {
	return n.ip
}

func (n Net) Netmask() IP {
	return makeIP(n.mask, n.ip.zone)
}

func (n Net) String() string {
	return fmt.Sprintf("%s/%d", n.ip, n.mask.ones())
}

type bitset struct {
	high uint64
	low  uint64
}

func mask128(str string) (bitset, error) {
	return parseBits(str, netmask128)
}

func mask32(str string) (bitset, error) {
	return parseBits(str, netmask32)
}

func parseBits(str string, limit uint64) (bitset, error) {
	n, err := strconv.ParseUint(str, 10, 8)
	if err != nil || n == 0 {
		return bitset{}, ErrInvalid
	}
	return setbits(n, limit)
}

func setbits(n, limit uint64) (bitset, error) {
	var b bitset
	if n > limit {
		return b, ErrInvalid
	}
	if limit == netmask128 {
		if n < netmask64 {
			diff := netmask64 - n
			b.high = ((1 << n) - 1) << diff
			return b, nil
		}
		if n >= netmask64 {
			b.high = (1 << 64) - 1
			n -= netmask64
			limit -= netmask64
		}
	}
	if n > 0 {
		diff := limit - n
		b.low = ((1 << n) - 1) << diff
	}
	return b, nil
}

func set8(a, b, c, d, e, f, g, h uint16) bitset {
	var bs bitset
	bs.high = uint64(a)<<48 | uint64(b)<<32 | uint64(c)<<16 | uint64(d)
	bs.low = uint64(e)<<48 | uint64(f)<<32 | uint64(g)<<16 | uint64(h)

	return bs
}

func set4(a, b, c, d uint8) bitset {
	var (
		ab = uint16(a)<<8 | uint16(b)
		cd = uint16(c)<<8 | uint16(d)
	)
	return set8(0, 0, 0, 0, 0, 0, ab, cd)
}

func (b bitset) equal(other bitset) bool {
	return b.high == other.high && b.low == other.low
}

func (b bitset) less(other bitset) bool {
	if b.high < other.high {
		return true
	}
	return b.low < other.low
}

func (b bitset) isZero() bool {
	return b.high == 0 && b.low == 0
}

func (b bitset) copy(ip net.IP) {
	copybytes(ip, b.high)
	copybytes(ip[8:], b.low)
}

func (b bitset) and(other bitset) bitset {
	other.high &= b.high
	other.low &= b.low
	return other
}

func (b bitset) zeros() int {
	var z int
	for _, set := range []uint64{b.low, b.high} {
		for i := 0; i < 64; i++ {
			b := set & 0x1
			if b != 0 {
				return z
			}
			z++
			set = set >> 1
		}
	}
	return z
}

func (b bitset) ones() int {
	return bits.OnesCount64(b.high) + bits.OnesCount64(b.low)
}

func parseIPv4(str string) (IP, error) {
	var (
		ip    = make([]uint8, net.IPv4len)
		parts = strings.Split(str, ".")
	)
	if len(parts) != net.IPv4len {
		return Zero, ErrInvalid
	}
	for i := 0; i < len(parts); i++ {
		b, err := strconv.ParseUint(parts[i], 10, 8)
		if err != nil {
			return Zero, ErrInvalid
		}
		ip[i] = uint8(b)
	}
	return IPv4(ip[0], ip[1], ip[2], ip[3]), nil
}

func parseIPv6(str string) (IP, error) {
	if str == "::" {
		return Zero, nil
	}
	var (
		ellipsis bool
		ip       = make([]uint16, net.IPv6len/2)
		parts    = strings.Split(str, ":")
	)
	if len(parts) > len(ip) || len(parts) <= 2 {
		return Zero, ErrInvalid
	}
	var j int
	for i := 0; i < len(parts); i++ {
		if parts[i] == "" {
			if ellipsis && i < len(parts)-1 {
				return Zero, ErrInvalid
			}
			ellipsis = i > 0
			j = len(ip) - (len(parts) - i) + 1
			continue
		}
		b, err := strconv.ParseUint(parts[i], 16, 16)
		if err != nil {
			return Zero, ErrInvalid
		}
		ip[j] = uint16(b)
		j++
	}
	if j < len(ip) {
		return Zero, ErrInvalid
	}
	return IPv6(ip[0], ip[1], ip[2], ip[3], ip[4], ip[5], ip[6], ip[7]), nil
}

func makeIP(set bitset, z zone) IP {
	return IP{
		set:  set,
		zone: z,
	}
}

const (
	colon = ':'
	dot   = '.'
)

func formatIPv4(ip IP) string {
	str := make([]byte, 0, 4)
	for i := 24; i >= 0; i -= 8 {
		b := (ip.set.low >> i) & 0xFF
		str = strconv.AppendUint(str, b, 10)
		if i > 0 {
			str = append(str, dot)
		}
	}
	return string(str)
}

func formatIPv6(ip IP) string {
	if ip.IsUndefined() {
		return "::"
	}
	type ptr struct {
		run int
		beg int
		end int
	}
	var (
		str  = make([]byte, 0, 8)
		curr ptr
		prev ptr
	)
	for _, i := range []uint64{ip.set.high, ip.set.low} {
		for j := 48; j >= 0; j -= 16 {
			b := (i >> j) & 0xFFFF
			if prev.run == 0 && b == 0 {
				prev.beg = len(str)
			}
			if prev.run >= 0 && b == 0 {
				prev.run++
			}
			if prev.run > 0 && b != 0 {
				prev.end = len(str)
				if prev.run >= curr.run {
					curr, prev = prev, ptr{}
				}
			}
			str = strconv.AppendUint(str, b, 16)
			if j > 0 {
				str = append(str, colon)
			}
		}
		if i == ip.set.high {
			str = append(str, colon)
		}
	}
	if curr.run > 0 || prev.run > 0 {
		if curr.run == 0 {
			curr = prev
		}
		if curr.end == 0 {
			curr.end = len(str)
		}
		str = append(str[:curr.beg], append([]byte{colon}, str[curr.end:]...)...)
		if curr.beg == 0 {
			str = append([]byte{colon}, str...)
		}
	}
	return string(str)
}

func defaultNetmaskIPv6(ip IP) int {
	switch {
	case ip.IsUndefined() || ip.IsLoopback():
		return netmask128
	case ip.IsMulticast():
		return netmask8
	case ip.IsLinkLocal():
		return netmask10
	default:
		return netmask64
	}
}

func defaultNetmaskIPv4(ip IP) int {
	var mask int
	switch ip.Class() {
	case ClassA:
		mask = netmask8
	case ClassB:
		mask = netmask16
	case ClassC:
		mask = netmask24
	case ClassD:
		mask = netmask4
	default:
		mask = netmask32
	}
	return mask
}

func countHostsNetv4(mask bitset) float64 {
	z := mask.zeros()
	if z <= 1 {
		return 1
	}
	return math.Pow(2, float64(z)) - 2
}

func countHostsNetv6(mask bitset) float64 {
	fmt.Println("count hosts v6:", mask.zeros())
	z := mask.zeros()
	if z <= 1 {
		return 1
	}
	return math.Pow(2, float64(z))
}

func copybytes(ip net.IP, part uint64) {
	ip[0] = byte(part >> 56)
	ip[1] = byte(part >> 48)
	ip[2] = byte(part >> 40)
	ip[3] = byte(part >> 32)
	ip[4] = byte(part >> 24)
	ip[5] = byte(part >> 16)
	ip[6] = byte(part >> 8)
	ip[7] = byte(part)
}

func allBytes(b net.IP, want byte) bool {
	for i := range b {
		if b[i] != want {
			return false
		}
	}
	return true
}
