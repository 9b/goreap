package main

import (
	"fmt"
	"net"
	"os"
	"strings"
)

func testStruct(any dnsStruct) string {
	s := "{ "
	i := 0
	any.Walk(func(val interface{}, name, tag string) bool {
		i++
		if i > 1 {
			s += ", "
		}
		s += "'" + strings.ToLower(name) + "':"
		switch tag {
		case "ipv4":
			i := *val.(*uint32)
			s += "'" + net.IPv4(byte(i>>24), byte(i>>16), byte(i>>8), byte(i)).String() + "'"
		case "ipv6":
			i := val.([]byte)
			s += net.IP(i).String()
		default:
			var i int64
			switch v := val.(type) {
			default:
				// can't really happen.
				s += "<unknown type>"
				return true
			case *string:
				s += "'" + *v + "'"
				return true
			case []byte:
				s += "'" + string(v) + "'"
				return true
			case *bool:
				if *v {
					s += "true"
				} else {
					s += "false"
				}
				return true
			case *int:
				i = int64(*v)
			case *uint:
				i = int64(*v)
			case *uint8:
				i = int64(*v)
			case *uint16:
				i = int64(*v)
			case *uint32:
				i = int64(*v)
			case *uint64:
				i = int64(*v)
			case *uintptr:
				i = int64(*v)
			}
			s += itoa(int(i))
		}
		return true
	})
	s += " }"
	return s
}

func unpackDns(msg []byte, dnsType uint16) (domain string, id uint16, ips []net.IP, raw []string) {
	d := new(dnsMsg)
	if !d.Unpack(msg) {
		// fmt.Fprintf(os.Stderr, "dns error (unpacking)\n")
		return
	}

	answers := make([]string, len(d.answer))
	if len(d.answer) > 0 {
		for i := 0; i < len(d.answer); i++ {
			answers[i] = testStruct(d.answer[i])
		}
	}
	raw = answers

	id = d.id

	if len(d.question) < 1 {
		// fmt.Fprintf(os.Stderr, "dns error (wrong question section)\n")
		return
	}

	domain = d.question[0].Name
	if len(domain) < 1 {
		// fmt.Fprintf(os.Stderr, "dns error (wrong domain in question)\n")
		return
	}

	_, addrs, err := answer(domain, "server", d, dnsType)
	if err == nil {
		switch (dnsType) {
		case dnsTypeA:
			ips = convertRR_A(addrs)
		case dnsTypeAAAA:
			ips = convertRR_AAAA(addrs)
		}
	}
	return
}

func packDns(domain string, id uint16, dnsType uint16) []byte {

	out := new(dnsMsg)
	out.id = id
	out.recursion_desired = true
	out.question = []dnsQuestion{
		{domain, dnsType, dnsClassINET},
	}

	msg, ok := out.Pack()
	if !ok {
		fmt.Fprintf(os.Stderr, "can't pack domain %s\n", domain)
		os.Exit(1)
	}
	return msg
}
