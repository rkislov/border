package mschap

import (
	"encoding/hex"
	"layeh.com/radius"
	"testing"
)

func unhex(s string) []byte { b, _ := hex.DecodeString(s); return b }
func TestRFC2759(t *testing.T) {
	hash := PasswordHash("clientPass")
	if hex.EncodeToString(hash) != "44ebba8d5312b8d611474411f56989ae" {
		t.Fatal("NT hash")
	}
	r := &Request{ID: 7, Challenge: unhex("5b5d7c7d7b3f2f3e3c2c602132262628"), Peer: unhex("21402324255e262a28295f2b3a337c7e"), Response: unhex("82309ecd8d708b5ea08faa3981cd83544233114a3d85d6df")}
	success, ok := r.Verify(hash, "User")
	if !ok || success != "S=407A5589115FD0D6209F510FE9C04566932CDA56" {
		t.Fatal(success, ok)
	}
	if _, ok = r.Verify(hash, "DOMAIN\\User"); !ok {
		t.Fatal("domain stripping")
	}
	if _, ok = r.Verify(hash, "user"); ok {
		t.Fatal("challenge username case lost")
	}
	if _, ok = r.Verify(PasswordHash("wrong"), "User"); ok {
		t.Fatal("wrong password")
	}
	p := radius.New(radius.CodeAccessAccept, []byte("secret"))
	if err := r.AddSuccess(p, success); err != nil {
		t.Fatal(err)
	}
	vendor, b, err := radius.VendorSpecific(p.Attributes.Get(26))
	if err != nil || vendor != 311 || len(b) != 45 || b[0] != 26 || b[1] != 45 || b[2] != 7 || string(b[3:]) != success {
		t.Fatal("success encoding")
	}
}
func add(p *radius.Packet, typ byte, b []byte) {
	v, _ := radius.NewVendorSpecific(311, append([]byte{typ, byte(len(b) + 2)}, b...))
	p.Attributes.Add(26, v)
}
func packet() *radius.Packet {
	p := radius.New(radius.CodeAccessRequest, []byte("secret"))
	add(p, 11, make([]byte, 16))
	add(p, 25, make([]byte, 50))
	return p
}
func TestParseStrict(t *testing.T) {
	if r, e := Parse(packet()); e != nil || r == nil {
		t.Fatal(r, e)
	}
	cases := map[string]func(*radius.Packet){
		"duplicate": func(p *radius.Packet) { add(p, 11, make([]byte, 16)) },
		"v1":        func(p *radius.Packet) { add(p, 1, make([]byte, 50)) },
		"pap":       func(p *radius.Packet) { p.Attributes.Add(2, make([]byte, 16)) },
		"eap":       func(p *radius.Packet) { p.Attributes.Add(79, []byte{2}) },
		"chap":      func(p *radius.Packet) { p.Attributes.Add(3, []byte{2}) },
		"missing":   func(p *radius.Packet) { p.Attributes.Del(26); add(p, 11, make([]byte, 16)) },
		"flags": func(p *radius.Packet) {
			p.Attributes.Del(26)
			add(p, 11, make([]byte, 16))
			b := make([]byte, 50)
			b[1] = 1
			add(p, 25, b)
		},
		"reserved": func(p *radius.Packet) {
			p.Attributes.Del(26)
			add(p, 11, make([]byte, 16))
			b := make([]byte, 50)
			b[18] = 1
			add(p, 25, b)
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			p := packet()
			mutate(p)
			if _, e := Parse(p); e == nil {
				t.Fatal("accepted malformed request")
			}
		})
	}
}
