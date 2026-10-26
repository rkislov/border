// Copyright 2026 Кислов Роман Сергеевич
// SPDX-License-Identifier: Apache-2.0
package radprofile

import (
	"encoding/binary"
	"fmt"
	"layeh.com/radius"
	"layeh.com/radius/rfc2865"
	"strconv"
	"strings"
)

type Attribute struct {
	Name   string
	Vendor uint32
	Code   byte
	Type   string
}
type Profile struct {
	ID, Name, Notes string
	Attributes      []Attribute
}

var Standard = []Attribute{{"Service-Type", 0, 6, "integer"}, {"Filter-Id", 0, 11, "string"}, {"Session-Timeout", 0, 27, "integer"}, {"Tunnel-Type", 0, 64, "integer"}, {"Tunnel-Medium-Type", 0, 65, "integer"}, {"Tunnel-Private-Group-ID", 0, 81, "string"}}
var Catalog = []Profile{
	{"keenetic", "Keenetic / KeeneticOS", "WPA Enterprise через стандартные RADIUS-атрибуты. SSH/VPN не подтверждены и отключены. Captive Portal UAM требует отдельного адаптера.", Standard},
	{"standard", "IETF / стандартный RADIUS", "Стандартные атрибуты RFC.", Standard},
	{"mikrotik", "MikroTik RouterOS", "Группа SSH должна существовать в RouterOS. VLAN — стандартные tunnel-атрибуты.", []Attribute{{"Mikrotik-Group", 14988, 3, "string"}, {"Mikrotik-Rate-Limit", 14988, 8, "string"}}},
	{"cisco", "Cisco IOS / IOS XE", "SSH: Cisco-AVPair shell:priv-lvl. Поддержка зависит от семейства и настроек AAA.", []Attribute{{"Cisco-AVPair", 9, 1, "string"}}},
	{"huawei", "Huawei VRP", "SSH: Huawei-Exec-Privilege. Диапазон прав проверьте для модели устройства.", []Attribute{{"Huawei-Exec-Privilege", 2011, 29, "integer"}}},
	{"fortinet", "FortiGate / FortiOS", "Настройте remote group и accprofile override на устройстве.", []Attribute{{"Fortinet-Group-Name", 12356, 1, "string"}, {"Fortinet-Access-Profile", 12356, 6, "string"}}},
	{"eltex", "Eltex", "Базовый профиль RFC; SSH-права задаются Service-Type. Специфические VSA требуют уточнения модели MES/ESR.", Standard},
	{"openvpn", "OpenVPN", "Требуется RADIUS-плагин с PAP и Message-Authenticator. Наличие профиля не устанавливает плагин на VPN-сервер.", Standard},
	{"strongswan", "strongSwan", "EAP-MSCHAPv2 ещё не реализован. Этот профиль пока справочный; VPN-авторизация недоступна.", Standard},
}

func Lookup(id string) (Profile, bool) {
	for _, p := range Catalog {
		if p.ID == id {
			return p, true
		}
	}
	return Profile{}, false
}

type Config struct{ Dictionary, Mode, Credential string }

func (c Config) Validate() error {
	if _, ok := Lookup(c.Dictionary); !ok {
		return fmt.Errorf("unknown RADIUS dictionary")
	}
	if c.Mode != "network" && c.Mode != "ssh" && c.Mode != "vpn" {
		return fmt.Errorf("mode must be network, ssh or vpn")
	}
	if c.Credential != "codes" && c.Credential != "directory" {
		return fmt.Errorf("credential must be codes or directory")
	}
	if c.Mode == "network" && c.Credential != "codes" {
		return fmt.Errorf("network mode currently uses codes and EAP-TLS")
	}
	if c.Dictionary == "keenetic" && c.Mode != "network" {
		return fmt.Errorf("Keenetic profile currently supports network access only")
	}
	if c.Dictionary == "strongswan" && c.Mode != "network" {
		return fmt.Errorf("strongSwan VPN EAP authentication is not implemented yet")
	}
	return nil
}

type Grant struct {
	NAS, Username, Mode, Role, Group, Filter string
	Privilege                                int
}

func (g Grant) Validate() error {
	if g.Username == "" || len(g.Username) > 200 || (g.Mode != "ssh" && g.Mode != "vpn") || g.Privilege < 0 || g.Privilege > 15 {
		return fmt.Errorf("invalid authorization grant")
	}
	for _, v := range []string{g.Role, g.Group, g.Filter} {
		if len(v) > 100 || strings.ContainsAny(v, "\r\n\x00") {
			return fmt.Errorf("invalid authorization attribute")
		}
	}
	return nil
}
func vsa(p *radius.Packet, vendor uint32, code byte, value []byte) error {
	b := append([]byte{code, byte(len(value) + 2)}, value...)
	a, err := radius.NewVendorSpecific(vendor, b)
	if err != nil {
		return err
	}
	p.Attributes.Add(26, a)
	return nil
}
func Apply(p *radius.Packet, c Config, g Grant) error {
	service := rfc2865.ServiceType(2)
	if c.Mode == "ssh" {
		service = 7
		if c.Dictionary == "mikrotik" {
			service = 1
		}
	}
	if err := rfc2865.ServiceType_Set(p, service); err != nil {
		return err
	}
	if g.Filter != "" {
		if err := rfc2865.FilterID_SetString(p, g.Filter); err != nil {
			return err
		}
	}
	switch c.Dictionary {
	case "mikrotik":
		if g.Group != "" {
			return vsa(p, 14988, 3, []byte(g.Group))
		}
	case "cisco":
		if c.Mode == "ssh" {
			return vsa(p, 9, 1, []byte("shell:priv-lvl="+strconv.Itoa(g.Privilege)))
		}
	case "huawei":
		if c.Mode == "ssh" {
			return vsa(p, 2011, 29, binary.BigEndian.AppendUint32(nil, uint32(g.Privilege)))
		}
	case "fortinet":
		if g.Group != "" {
			if err := vsa(p, 12356, 1, []byte(g.Group)); err != nil {
				return err
			}
		}
		if c.Mode == "ssh" && g.Role != "" {
			return vsa(p, 12356, 6, []byte(g.Role))
		}
	}
	return nil
}
