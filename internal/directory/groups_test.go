package directory

import (
	"crypto/tls"
	"crypto/x509"
	ber "github.com/go-asn1-ber/asn1-ber"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
)

func TestLDAPSReturnsGroupsOnlyAfterSuccessfulBind(t *testing.T) {
	source := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	config := source.TLS.Clone()
	cert := source.Certificate()
	source.Close()
	listener, e := tls.Listen("tcp", "127.0.0.1:0", config)
	if e != nil {
		t.Fatal(e)
	}
	defer listener.Close()
	roots := x509.NewCertPool()
	roots.AddCert(cert)
	result := func(id int64, tag ber.Tag, code int64) *ber.Packet {
		p := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "")
		p.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, id, ""))
		r := ber.Encode(ber.ClassApplication, ber.TypeConstructed, tag, nil, "")
		r.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagEnumerated, code, ""))
		r.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "", ""))
		r.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "", ""))
		p.AppendChild(r)
		return p
	}
	done := make(chan error, 1)
	go func() {
		for range 2 {
			conn, e := listener.Accept()
			if e != nil {
				done <- e
				return
			}
			func() {
				defer conn.Close()
				for {
					p, e := ber.ReadPacket(conn)
					if e != nil {
						return
					}
					id := p.Children[0].Value.(int64)
					op := p.Children[1]
					switch op.Tag {
					case 0:
						code := int64(0)
						if op.Children[2].Data.String() != "correct-password" {
							code = 49
						}
						conn.Write(result(id, 1, code).Bytes())
					case 3:
						requested := false
						for _, attr := range op.Children[7].Children {
							if attr.Data.String() == "memberOf" {
								requested = true
							}
						}
						if !requested {
							done <- net.InvalidAddrError("memberOf not requested")
							return
						}
						packet := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "")
						packet.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, id, ""))
						entry := ber.Encode(ber.ClassApplication, ber.TypeConstructed, 4, nil, "")
						entry.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "uid=alice,dc=test", ""))
						attributes := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "")
						for name, values := range map[string][]string{"uid": {"alice"}, "mail": {"alice@example.test"}, "memberOf": {"cn=staff,dc=test", "cn=wifi,dc=test"}} {
							attribute := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "")
							attribute.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, name, ""))
							set := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSet, nil, "")
							for _, value := range values {
								set.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, value, ""))
							}
							attribute.AppendChild(set)
							attributes.AppendChild(attribute)
						}
						entry.AppendChild(attributes)
						packet.AppendChild(entry)
						conn.Write(packet.Bytes())
						conn.Write(result(id, 5, 0).Bytes())
					case 2:
						return
					}
				}
			}()
		}
		done <- nil
	}()
	l := &LDAP{URL: "ldaps://" + listener.Addr().String(), TLS: &tls.Config{RootCAs: roots, ServerName: "127.0.0.1", MinVersion: tls.VersionTLS12}, BaseDN: "dc=test", BindDN: "cn=reader", BindPassword: "correct-password", UserAttribute: "uid"}
	i, e := l.Authenticate(t.Context(), "alice", "correct-password")
	if e != nil || len(i.Groups) != 2 || !strings.Contains(strings.Join(i.Groups, " "), "cn=staff") {
		t.Fatal("groups", i, e)
	}
	i, e = l.Authenticate(t.Context(), "alice", "wrong")
	if e == nil || len(i.Groups) != 0 {
		t.Fatal("groups before successful authentication", strconv.Itoa(len(i.Groups)))
	}
	if e = <-done; e != nil {
		t.Fatal(e)
	}
}
