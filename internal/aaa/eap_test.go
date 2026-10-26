package aaa

import (
	"bytes"
	"layeh.com/radius"
	"layeh.com/radius/vendors/microsoft"
	"testing"
)

func TestMPPEKeyEncoding(t *testing.T) {
	request := radius.New(radius.CodeAccessRequest, []byte(testSecret))
	response := request.Response(radius.CodeAccessAccept)
	key := make([]byte, 128)
	for i := range key {
		key[i] = byte(i)
	}
	if err := setMPPEKeys(response, key); err != nil {
		t.Fatal(err)
	}
	if got := microsoft.MSMPPERecvKey_Get(response, request); !bytes.Equal(got, key[:32]) {
		t.Fatal("wrong receiving key")
	}
	if got := microsoft.MSMPPESendKey_Get(response, request); !bytes.Equal(got, key[32:64]) {
		t.Fatal("wrong sending key")
	}
	var salts [][]byte
	for _, a := range response.Attributes {
		if a.Type != 26 {
			continue
		}
		vendor, data, err := radius.VendorSpecific(a.Attribute)
		if err != nil || vendor != 311 {
			t.Fatal("invalid Microsoft VSA")
		}
		if len(data) < 4 || data[2]&0x80 == 0 {
			t.Fatal("invalid MPPE salt")
		}
		salts = append(salts, data[2:4])
	}
	if len(salts) != 2 || bytes.Equal(salts[0], salts[1]) {
		t.Fatal("MPPE salts must be distinct")
	}
	if err := setMPPEKeys(response, key[:64]); err == nil {
		t.Fatal("short key accepted")
	}
}
