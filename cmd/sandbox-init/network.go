// Guest IP-layer setup via raw netlink. Replaces the kernel's
// `ip=...` cmdline + CONFIG_IP_PNP path so we can drop those from
// the kernel.
//
// Three RTNETLINK messages are sufficient for static-IP setup:
//   1. RTM_NEWLINK with IFF_UP — bring iface up
//   2. RTM_NEWADDR with IFA_LOCAL/IFA_ADDRESS — assign the IP
//   3. RTM_NEWROUTE with RTA_GATEWAY — install default route (optional)
//
// Each carries NLM_F_REQUEST | NLM_F_ACK; we drain the ack and verify
// the kernel accepted (NLMSG_ERROR with code 0). Any non-zero error
// short-circuits and bubbles up.
//
// Implementation uses raw `golang.org/x/sys/unix` syscalls — already
// a dependency. ~250 lines, no new third-party libs.

package main

import (
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"syscall"
	"unsafe"

	"github.com/kuasar-sandbox/guest-runtime/pkg/guestabi/proto"
	"golang.org/x/sys/unix"
)

// bringUpLoopback sets IFF_UP on the `lo` interface. The kernel creates the
// loopback device DOWN; bringing it up makes the kernel auto-assign the
// host-scope 127.0.0.1/8 and ::1/128, so no RTM_NEWADDR is needed. Done
// unconditionally on cold start (independent of any NetworkSpec) — guest apps
// that bind localhost would otherwise hit EADDRNOTAVAIL.
func bringUpLoopback() error {
	ifindex, err := readIfindex("lo")
	if err != nil {
		return fmt.Errorf("ifindex lo: %w", err)
	}
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW|unix.SOCK_CLOEXEC, unix.NETLINK_ROUTE)
	if err != nil {
		return fmt.Errorf("netlink socket: %w", err)
	}
	defer unix.Close(fd)
	if err := unix.Bind(fd, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return fmt.Errorf("netlink bind: %w", err)
	}
	if err := nlSendLinkUp(fd, 1, ifindex, 0); err != nil {
		return fmt.Errorf("link up lo: %w", err)
	}
	return nil
}

// applyNetwork configures the guest IP layer on cold start: a fresh iface,
// additive (RTM_NEWADDR with NLM_F_EXCL, route with NLM_F_EXCL).
func applyNetwork(spec *proto.NetworkSpec) error { return applyNetworkMode(spec, false) }

// applyNetworkReplace re-applies the IP layer on restore. The iface is already
// configured from the snapshot, so it flushes the iface's existing global
// addresses first and uses REPLACE semantics for the new address + default
// route — letting a clone restored from a golden snapshot take a fresh
// network identity without inheriting the snapshot's IP.
//
// The common restore (same node or cross-node with an unchanged guest
// identity) carries exactly the values the snapshot already applied; rewriting
// them costs 7-15ms of netlink traffic for no effect. Skip when every field
// already matches.
func applyNetworkReplace(spec *proto.NetworkSpec) error {
	if ok, err := networkAlreadyApplied(spec); err == nil && ok {
		logf("restore network: already applied; skipping re-apply")
		return nil
	}
	return applyNetworkMode(spec, true)
}

// networkAlreadyApplied reports whether the guest IP layer already matches the
// requested spec. Any unverifiable or missing field returns false so the caller
// performs the full replace.
func networkAlreadyApplied(spec *proto.NetworkSpec) (bool, error) {
	if spec == nil {
		return true, nil
	}
	if spec.Hostname != "" {
		current, err := os.Hostname()
		if err != nil || current != spec.Hostname {
			return false, err
		}
	}
	if spec.IPCIDR == "" {
		return true, nil
	}
	iface := spec.Interface
	if iface == "" {
		iface = "eth0"
	}
	dev, err := net.InterfaceByName(iface)
	if err != nil {
		return false, err
	}
	if spec.MTU != 0 && dev.MTU != spec.MTU {
		return false, nil
	}
	ip, ipnet, err := net.ParseCIDR(spec.IPCIDR)
	if err != nil {
		return false, err
	}
	if ip.To4() == nil {
		// IPv6 default routes are not inspected here; take the full path.
		return false, nil
	}
	wantOnes, wantBits := ipnet.Mask.Size()
	addrs, err := dev.Addrs()
	if err != nil {
		return false, err
	}
	addrMatch := false
	for _, addr := range addrs {
		ipnet, ok := addr.(*net.IPNet)
		if !ok || !ipnet.IP.Equal(ip) {
			continue
		}
		ones, bits := ipnet.Mask.Size()
		if ones == wantOnes && bits == wantBits {
			addrMatch = true
			break
		}
	}
	if !addrMatch {
		return false, nil
	}
	if spec.Nexthop != "" {
		match, err := defaultRouteMatches(spec.Nexthop)
		if err != nil || !match {
			return false, err
		}
	}
	return true, nil
}

// defaultRouteMatches reports whether the IPv4 default route already uses
// nexthop. /proc/net/route stores Destination/Mask/Gateway as little-endian
// hex.
func defaultRouteMatches(nexthop string) (bool, error) {
	raw, err := os.ReadFile("/proc/net/route")
	if err != nil {
		return false, err
	}
	want := net.ParseIP(nexthop).To4()
	if want == nil {
		return false, nil
	}
	for i, line := range strings.Split(string(raw), "\n") {
		if i == 0 || strings.TrimSpace(line) == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 8 {
			continue
		}
		// Iface Destination Gateway Flags RefCnt Use Metric Mask MTU ...
		if fields[1] != "00000000" || fields[7] != "00000000" {
			continue // not a default route
		}
		gw, err := strconv.ParseUint(fields[2], 16, 32)
		if err != nil {
			continue
		}
		var got [4]byte
		binary.LittleEndian.PutUint32(got[:], uint32(gw))
		return net.IP(got[:]).Equal(want), nil
	}
	return false, nil
}

// applyNetworkMode executes hostname + bring-iface-up(+MTU) + assign-IP +
// default-route in order. When replace is true it flushes existing global
// addresses before assigning and uses REPLACE instead of EXCL. Any step's
// failure aborts subsequent steps and returns the error.
func applyNetworkMode(spec *proto.NetworkSpec, replace bool) error {
	if spec == nil {
		return nil
	}
	if spec.Hostname != "" {
		if err := unix.Sethostname([]byte(spec.Hostname)); err != nil {
			return fmt.Errorf("sethostname %q: %w", spec.Hostname, err)
		}
	}
	if spec.IPCIDR == "" {
		return nil
	}
	iface := spec.Interface
	if iface == "" {
		iface = "eth0"
	}
	ifindex, err := readIfindex(iface)
	if err != nil {
		return fmt.Errorf("ifindex %s: %w", iface, err)
	}

	ip, ipnet, err := net.ParseCIDR(spec.IPCIDR)
	if err != nil {
		return fmt.Errorf("parse cidr %q: %w", spec.IPCIDR, err)
	}
	prefixLen, _ := ipnet.Mask.Size()
	family := unix.AF_INET
	if ip.To4() == nil {
		family = unix.AF_INET6
	}

	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW|unix.SOCK_CLOEXEC, unix.NETLINK_ROUTE)
	if err != nil {
		return fmt.Errorf("netlink socket: %w", err)
	}
	defer unix.Close(fd)
	if err := unix.Bind(fd, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return fmt.Errorf("netlink bind: %w", err)
	}

	seq := uint32(1)

	if err := nlSendLinkUp(fd, seq, ifindex, spec.MTU); err != nil {
		return fmt.Errorf("link up %s: %w", iface, err)
	}
	seq++

	if replace {
		if err := flushAddrs(fd, &seq, ifindex, family); err != nil {
			return fmt.Errorf("flush addrs on %s: %w", iface, err)
		}
	}

	if err := nlSendAddrAdd(fd, seq, ifindex, family, ip, prefixLen, replace); err != nil {
		return fmt.Errorf("addr add %s on %s: %w", spec.IPCIDR, iface, err)
	}
	seq++

	if spec.Nexthop != "" {
		gw := net.ParseIP(spec.Nexthop)
		if gw == nil {
			return fmt.Errorf("parse nexthop %q: invalid IP", spec.Nexthop)
		}
		gwFamily := unix.AF_INET
		if gw.To4() == nil {
			gwFamily = unix.AF_INET6
		}
		if err := nlSendDefaultRoute(fd, seq, ifindex, gwFamily, gw, replace); err != nil {
			return fmt.Errorf("default route via %s: %w", spec.Nexthop, err)
		}
	}
	return nil
}

// readIfindex returns the kernel-assigned interface index for name via
// sysfs (one open+read+parse, no netlink round-trip).
func readIfindex(name string) (int32, error) {
	data, err := os.ReadFile("/sys/class/net/" + name + "/ifindex")
	if err != nil {
		return 0, err
	}
	idx, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil {
		return 0, err
	}
	return int32(idx), nil
}

// --- netlink message construction ---------------------------------

const nlAlignTo = 4

// nlAlign rounds len up to 4 bytes (NLMSG_ALIGN).
func nlAlign(n int) int { return (n + nlAlignTo - 1) &^ (nlAlignTo - 1) }

// nlAttr appends a TLV attribute to buf and returns the new buf.
func nlAttr(buf []byte, attrType uint16, value []byte) []byte {
	hdrSize := 4 // sizeof(rtattr)
	totalLen := hdrSize + len(value)
	padded := nlAlign(totalLen)
	a := make([]byte, padded)
	binary.LittleEndian.PutUint16(a[0:2], uint16(totalLen))
	binary.LittleEndian.PutUint16(a[2:4], attrType)
	copy(a[4:], value)
	return append(buf, a...)
}

// nlSend sends a single message with NLM_F_REQUEST|NLM_F_ACK and waits
// for the kernel ack (NLMSG_ERROR with err==0).
func nlSend(fd int, msgType uint16, flags uint16, seq uint32, body []byte) error {
	const hdrSize = unix.SizeofNlMsghdr
	totalLen := hdrSize + len(body)
	buf := make([]byte, totalLen)
	hdr := (*unix.NlMsghdr)(unsafe.Pointer(&buf[0]))
	hdr.Len = uint32(totalLen)
	hdr.Type = msgType
	hdr.Flags = unix.NLM_F_REQUEST | unix.NLM_F_ACK | flags
	hdr.Seq = seq
	hdr.Pid = 0
	copy(buf[hdrSize:], body)

	if err := unix.Sendto(fd, buf, 0, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return fmt.Errorf("sendto: %w", err)
	}

	rbuf := make([]byte, 4096)
	for {
		n, _, err := unix.Recvfrom(fd, rbuf, 0)
		if err != nil {
			return fmt.Errorf("recvfrom: %w", err)
		}
		if n < hdrSize {
			return fmt.Errorf("short recv %d", n)
		}
		rhdr := (*unix.NlMsghdr)(unsafe.Pointer(&rbuf[0]))
		if rhdr.Type == unix.NLMSG_ERROR {
			// payload is int32 errno, then echoed request hdr
			errno := int32(binary.LittleEndian.Uint32(rbuf[hdrSize : hdrSize+4]))
			if errno == 0 {
				return nil
			}
			return fmt.Errorf("netlink error %d (%s)", -errno, unix.Errno(-errno))
		}
		if rhdr.Flags&unix.NLM_F_MULTI != 0 && rhdr.Type != unix.NLMSG_DONE {
			continue
		}
		// unexpected reply (multipart on a non-multipart op)
		return fmt.Errorf("unexpected netlink reply type %d", rhdr.Type)
	}
}

// nlSendLinkUp issues RTM_NEWLINK setting IFF_UP on ifindex, and — when
// mtu > 0 — an IFLA_MTU attribute to set the interface MTU.
func nlSendLinkUp(fd int, seq uint32, ifindex int32, mtu int) error {
	body := make([]byte, unix.SizeofIfInfomsg)
	ifi := (*unix.IfInfomsg)(unsafe.Pointer(&body[0]))
	ifi.Family = unix.AF_UNSPEC
	ifi.Index = ifindex
	ifi.Flags = unix.IFF_UP
	ifi.Change = unix.IFF_UP
	if mtu > 0 {
		raw := make([]byte, 4)
		binary.LittleEndian.PutUint32(raw, uint32(mtu))
		body = nlAttr(body, unix.IFLA_MTU, raw)
	}
	return nlSend(fd, unix.RTM_NEWLINK, 0, seq, body)
}

// addFlags returns the create flags for RTM_NEW* ops: REPLACE when replacing
// (restore), EXCL otherwise (cold; fail if it already exists).
func addFlags(replace bool) uint16 {
	if replace {
		return unix.NLM_F_CREATE | unix.NLM_F_REPLACE
	}
	return unix.NLM_F_CREATE | unix.NLM_F_EXCL
}

// nlSendAddrAdd issues RTM_NEWADDR with IFA_LOCAL + IFA_ADDRESS.
func nlSendAddrAdd(fd int, seq uint32, ifindex int32, family int, ip net.IP, prefix int, replace bool) error {
	body := make([]byte, unix.SizeofIfAddrmsg)
	ifa := (*unix.IfAddrmsg)(unsafe.Pointer(&body[0]))
	ifa.Family = uint8(family)
	ifa.Prefixlen = uint8(prefix)
	ifa.Index = uint32(ifindex)
	ifa.Scope = unix.RT_SCOPE_UNIVERSE

	raw := addrBytes(family, ip)
	body = nlAttr(body, unix.IFA_LOCAL, raw)
	body = nlAttr(body, unix.IFA_ADDRESS, raw)

	return nlSend(fd, unix.RTM_NEWADDR, addFlags(replace), seq, body)
}

// nlSendDefaultRoute issues RTM_NEWROUTE for 0.0.0.0/0 (or ::/0) via gw on ifindex.
func nlSendDefaultRoute(fd int, seq uint32, ifindex int32, family int, gw net.IP, replace bool) error {
	body := make([]byte, unix.SizeofRtMsg)
	rt := (*unix.RtMsg)(unsafe.Pointer(&body[0]))
	rt.Family = uint8(family)
	rt.Dst_len = 0 // 0.0.0.0/0 or ::/0
	rt.Src_len = 0
	rt.Tos = 0
	rt.Table = unix.RT_TABLE_MAIN
	rt.Protocol = unix.RTPROT_BOOT
	rt.Scope = unix.RT_SCOPE_UNIVERSE
	rt.Type = unix.RTN_UNICAST
	rt.Flags = 0

	body = nlAttr(body, unix.RTA_GATEWAY, addrBytes(family, gw))

	// OIF (output interface) — 4 bytes LE int32 in NlAttr
	oifBytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(oifBytes, uint32(ifindex))
	body = nlAttr(body, unix.RTA_OIF, oifBytes)

	return nlSend(fd, unix.RTM_NEWROUTE, addFlags(replace), seq, body)
}

// addrBytes returns the 4- or 16-byte wire form of ip for the family.
func addrBytes(family int, ip net.IP) []byte {
	if family == unix.AF_INET {
		return ip.To4()
	}
	return ip.To16()
}

// flushAddrs removes every global-scope address of `family` on ifindex
// (RTM_GETADDR dump → RTM_DELADDR each). Used on restore so a re-identified
// clone does not keep the golden snapshot's IP. Link/host-scope addresses
// (e.g. IPv6 link-local) are left untouched. *seq is advanced per message.
func flushAddrs(fd int, seq *uint32, ifindex int32, family int) error {
	addrs, err := nlDumpAddrs(fd, *seq, ifindex, family)
	*seq++
	if err != nil {
		return err
	}
	for _, a := range addrs {
		if err := nlSendAddrDel(fd, *seq, ifindex, family, a.ip, a.prefix); err != nil {
			return fmt.Errorf("del %s/%d: %w", a.ip, a.prefix, err)
		}
		*seq++
	}
	return nil
}

type addrEntry struct {
	ip     net.IP
	prefix int
}

// nlDumpAddrs sends an RTM_GETADDR dump and collects the global-scope
// addresses of `family` on ifindex from the multipart reply.
func nlDumpAddrs(fd int, seq uint32, ifindex int32, family int) ([]addrEntry, error) {
	const hdrSize = unix.SizeofNlMsghdr
	body := make([]byte, unix.SizeofIfAddrmsg)
	ifa := (*unix.IfAddrmsg)(unsafe.Pointer(&body[0]))
	ifa.Family = uint8(family)

	buf := make([]byte, hdrSize+len(body))
	h := (*unix.NlMsghdr)(unsafe.Pointer(&buf[0]))
	h.Len = uint32(len(buf))
	h.Type = unix.RTM_GETADDR
	h.Flags = unix.NLM_F_REQUEST | unix.NLM_F_DUMP
	h.Seq = seq
	copy(buf[hdrSize:], body)
	if err := unix.Sendto(fd, buf, 0, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return nil, fmt.Errorf("sendto getaddr: %w", err)
	}

	var out []addrEntry
	rbuf := make([]byte, 8192)
	for {
		n, _, err := unix.Recvfrom(fd, rbuf, 0)
		if err != nil {
			return nil, fmt.Errorf("recvfrom getaddr: %w", err)
		}
		data := rbuf[:n]
		for len(data) >= hdrSize {
			mh := (*unix.NlMsghdr)(unsafe.Pointer(&data[0]))
			l := int(mh.Len)
			if l < hdrSize || l > len(data) {
				return out, nil // truncated/malformed — stop with what we have
			}
			switch mh.Type {
			case unix.NLMSG_DONE:
				return out, nil
			case unix.NLMSG_ERROR:
				errno := int32(binary.LittleEndian.Uint32(data[hdrSize : hdrSize+4]))
				if errno != 0 {
					return out, fmt.Errorf("getaddr dump: netlink error %d", -errno)
				}
				return out, nil
			case unix.RTM_NEWADDR:
				if e, ok := parseAddrEntry(data[hdrSize:l], ifindex, family); ok {
					out = append(out, e)
				}
			}
			data = data[nlAlign(l):]
		}
	}
}

// parseAddrEntry extracts (ip, prefix) from an RTM_NEWADDR payload iff it is a
// global-scope address of the given family on ifindex.
func parseAddrEntry(p []byte, ifindex int32, family int) (addrEntry, bool) {
	if len(p) < unix.SizeofIfAddrmsg {
		return addrEntry{}, false
	}
	ifa := (*unix.IfAddrmsg)(unsafe.Pointer(&p[0]))
	if int32(ifa.Index) != ifindex || int(ifa.Family) != family || ifa.Scope != unix.RT_SCOPE_UNIVERSE {
		return addrEntry{}, false
	}
	attrs := p[unix.SizeofIfAddrmsg:]
	var ip net.IP
	for len(attrs) >= 4 {
		alen := int(binary.LittleEndian.Uint16(attrs[0:2]))
		atype := binary.LittleEndian.Uint16(attrs[2:4])
		if alen < 4 || alen > len(attrs) {
			break
		}
		val := attrs[4:alen]
		if atype == unix.IFA_LOCAL || (atype == unix.IFA_ADDRESS && ip == nil) {
			ip = append(net.IP(nil), val...)
		}
		attrs = attrs[nlAlign(alen):]
	}
	if ip == nil {
		return addrEntry{}, false
	}
	return addrEntry{ip: ip, prefix: int(ifa.Prefixlen)}, true
}

// nlSendAddrDel issues RTM_DELADDR for ip/prefix on ifindex.
func nlSendAddrDel(fd int, seq uint32, ifindex int32, family int, ip net.IP, prefix int) error {
	body := make([]byte, unix.SizeofIfAddrmsg)
	ifa := (*unix.IfAddrmsg)(unsafe.Pointer(&body[0]))
	ifa.Family = uint8(family)
	ifa.Prefixlen = uint8(prefix)
	ifa.Index = uint32(ifindex)

	raw := addrBytes(family, ip)
	body = nlAttr(body, unix.IFA_LOCAL, raw)
	body = nlAttr(body, unix.IFA_ADDRESS, raw)

	return nlSend(fd, unix.RTM_DELADDR, 0, seq, body)
}

// _ keeps the syscall import live in case future revisions need raw fcntls.
var _ = syscall.SOCK_STREAM
