// Copyright 2026 Кислов Роман Сергеевич
// SPDX-License-Identifier: Apache-2.0
package radprofile

// Capability describes Border's implementation separately from NAS verification.
// Available does not certify a device model or firmware.
type Capability struct {
	ID, Name                   string
	Available                  bool
	Verification, Requirements string
}
type Capabilities struct {
	Dictionary string
	Modes      []string
	Features   []Capability
}

func SupportsMode(dictionary, mode string) bool {
	if _, ok := Lookup(dictionary); !ok {
		return false
	}
	if mode != "network" && mode != "ssh" && mode != "vpn" {
		return false
	}
	if dictionary == "keenetic" {
		return mode == "network"
	}
	// Preserve existing server constraints for saved configurations.
	return dictionary != "strongswan" || mode != "ssh"
}

func Describe(dictionary string) (Capabilities, bool) {
	if _, ok := Lookup(dictionary); !ok {
		return Capabilities{}, false
	}
	c := Capabilities{Dictionary: dictionary, Modes: []string{}, Features: []Capability{}}
	for _, mode := range []string{"network", "ssh", "vpn"} {
		if SupportsMode(dictionary, mode) {
			c.Modes = append(c.Modes, mode)
		}
	}
	add := func(id, name string, available bool, requirements string) {
		verification := "Не проверено на оборудовании"
		if !available {
			verification = "Не реализовано / запрещено профилем"
		}
		c.Features = append(c.Features, Capability{id, name, available, verification, requirements})
	}
	add("network", "Сетевой доступ / VLAN", SupportsMode(dictionary, "network"), "802.1X или MAB на NAS; динамический VLAN через Tunnel-Type, Tunnel-Medium-Type и Tunnel-Private-Group-ID. Для VPN-плагинов применимость проверяется отдельно.")
	add("ssh", "Авторизация SSH", SupportsMode(dictionary, "ssh"), "Включить AAA и настроить локальные группы/уровни прав. Проверить поддерживаемый метод RADIUS на конкретной модели.")
	add("vpn", "Авторизация VPN", SupportsMode(dictionary, "vpn"), "Согласовать PAP или EAP-MSCHAPv2 с политикой и VPN-клиентом. OpenVPN требует отдельного RADIUS-плагина.")
	add("eap_tls", "EAP-TLS 1.2", true, "802.1X NAS, доверенный CA и управляемый клиентский сертификат. Наличие реализации Border не означает поддержку VPN-плагином.")
	add("peap", "PEAP-MSCHAPv2 / TTLS-PAP", true, "TLS 1.2; выбрать метод в политике local/directory для сети. Проверять CA и имя сервера на клиенте. Проверено eapol_test; физические NAS не проверены. Без resumption и PEAP cryptobinding.")
	add("accounting", "Учёт сессий", true, "Start, Interim, Stop; Class без изменений, Event-Timestamp, Acct-Session-Time. Синхронизировать часы и включить accounting на NAS.")
	add("disconnect", "Отзыв доступа", true, "RFC 5176, общий секрет, доступ к CoA-порту. Связь с разрешением обязательна для автоматического отзыва; ACK не гарантирован словарём.")
	add("coa_vlan", "Смена VLAN через CoA", true, "NAS должен поддерживать CoA и tunnel-атрибуты для данного вида сессии; требуется проверка на модели.")
	add("radsec", "RadSec", false, "Не реализовано; RADIUS UDP размещать в защищённой сети.")
	add("guest_activation", "Автоматическое открытие гостевого доступа", dictionary == "mikrotik" || dictionary == "keenetic", "Адаптеры RouterOS HotSpot и Netcraze/Chilli. Фиксированный гостевой сегмент, RADIUS и Accounting/Class обязательны. Общая очередь SMS/email/OIDC; настройки адаптера задаются отдельно для NAS.")
	if dictionary == "keenetic" {
		for i := range c.Features {
			f := &c.Features[i]
			switch f.ID {
			case "guest_activation":
				f.Requirements = "Chilli UAM и RCI; HTTPS с закреплённым сертификатом либо защищённый туннель. Подписанный UAM Session-ID должен совпасть с Acct-Session-Id в Access-Request. Гостевой мост и сегмент настраиваются заранее. Успех только по Class/Accounting."
				f.Verification = "Встроенный адаптер: Ultra NC-1812, NDMS 5.1.8, 23.11.2026. Email, Accounting, перезапуск, срок и Disconnect-ACK проверены."
			case "peap":
				f.Requirements = "TLS 1.2; выбрать метод local/directory для сети. Проверять CA и имя сервера на клиенте. TTLS/PAP проверен с локальным пользователем; доменный вход на этом NAS ещё не проверен. Без resumption и PEAP cryptobinding."
				f.Verification = "TTLS/PAP: Ultra NC-1812 и macOS, 23.11.2026. PEAP на этом NAS не проверен."
			case "accounting", "disconnect":
				f.Verification = "Chilli: Ultra NC-1812, 23.11.2026. Для WPA-Enterprise не подтверждено."
			}
		}
	}
	if dictionary == "mikrotik" || dictionary == "strongswan" {
		for i := range c.Features {
			f := &c.Features[i]
			if dictionary == "mikrotik" && f.ID == "guest_activation" {
				f.Verification = "Лаборатория: CHR 7.23.8 HotSpot, 01.11.2026"
			}
			if f.ID == "vpn" || f.ID == "accounting" || f.ID == "disconnect" {
				f.Verification = "Лаборатория: strongSwan IKEv2, 30.10.2026"
				if dictionary == "mikrotik" {
					f.Verification = "Лаборатория: CHR 7.23.8 IKEv2, 30.10.2026"
				}
			}
		}
	}
	if dictionary == "mikrotik" {
		c.Features[1].Verification = "Лаборатория: CHR 7.23.8 SSH MS-CHAPv2"
		c.Features[5].Requirements += " RouterOS IPsec в стенде не возвращает Class: потеря Start оставляет сессию без автоматического отзыва."
		c.Features[6].Requirements += " SSH CHR требует отдельного SSH-адаптера после NAK 406; VPN проверен через RADIUS."
	}
	return c, true
}
