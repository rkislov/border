# Профили NAS и режимы доступа

В «Сетевых устройствах» выбираются RADIUS-словарь, назначение NAS и способ проверки пользователя. Встроенные профили содержат небольшой проверенный набор атрибутов; это не полные словари FreeRADIUS и не подтверждение совместимости со всеми моделями производителя.

Одна запись IP NAS использует один режим:
- Сеть: MAB, EAP-TLS, одноразовые PAP-коды, гостевые разрешения.
- SSH: PAP-проверка пользователя и отдельное разрешение в разделе «Разрешения SSH и VPN».
- VPN: PAP-проверка и отдельное разрешение. Ответ содержит Framed-User; сетевые VLAN не передаются.

Для SSH/VPN доступны коды Border или пароль настроенного AD/FreeIPA (LDAP с TLS). Пустое разрешение, неверный пароль, MAB, CHAP и EAP в этих двух режимах не дают доступ. Пользователи панели управления не становятся администраторами NAS. Совместное обслуживание сети, SSH и VPN с одного IP с автоматическим разделением запросов пока не реализовано.

PAP между NAS и Border требует защищённой сети или VPN-транспорта. Каждый Access-Request должен содержать Message-Authenticator. MS-CHAPv2 реализован для SSH с политикой доступа; для домена нужен настроенный Samba/winbind helper и LDAP. RadSec, PEAP и TTLS пока не реализованы. Профиль strongSwan поддерживает IKEv2 с EAP-MSCHAPv2 через VPN-политику локального или доменного пользователя; см. [настройку VPN](VPN-EAP-MSCHAPV2.md). OpenVPN требует отдельно установленного совместимого RADIUS-плагина.

## Атрибуты

- MikroTik: Mikrotik-Group (14988:3), существующая локальная группа RouterOS. SSH-вход RouterOS 7.23.8 через MS-CHAPv2 проверен на CHR: локальные пользователи с включённой совместимостью и доменные пользователи через Samba/winbind. См. [проверку CHR в UTM](MIKROTIK-UTM.md).
- Cisco IOS/IOS XE: Cisco-AVPair (9:1), shell:priv-lvl для SSH; device-traffic-class=voice только в сетевом профиле Cisco.
- Huawei: Huawei-Exec-Privilege (2011:29). Уровень должен поддерживаться моделью и прошивкой.
- FortiGate: Fortinet-Group-Name (12356:1), Fortinet-Access-Profile (12356:6). Remote group и профиль настраиваются также на FortiGate.
- Eltex: базовые RFC-атрибуты, включая Service-Type и Filter-Id. Специфические VSA и шаблоны MES/ESR ещё требуют проверки.
- Keenetic: базовый сетевой профиль WPA Enterprise. SSH/VPN не подтверждены и заблокированы. Встроенный UAM/Chilli не совместим автоматически с подписанным редиректом Border; нужен адаптер.
- IETF/OpenVPN: Service-Type, Filter-Id, Session-Timeout; сетевые VLAN в режиме сети.

Проверки кодирования атрибутов и запретов выполняются автоматически. Испытания на физических устройствах перечисленных производителей ещё не проведены. Назначение профиля не меняет конфигурацию самого оборудования.

## Источники форматов

- [MikroTik RADIUS](https://help.mikrotik.com/docs/spaces/ROS/pages/328097/RADIUS)
- [Cisco AAA](https://developer.cisco.com/site/odp/documents/xe-user-guide-xconf-aaa/)
- [Huawei VSA 2011:29](https://community.cisco.com/kxiwq67737/attachments/kxiwq67737/4561-docs-security/4143/1/cisco_acs_radius_migration_with_huawei_nes.pdf)
- [Fortinet группы и профили](https://docs.fortinet.com/document/fortiswitch/7.2.7/administration-guide/288914)
- [Keenetic WPA Enterprise](https://support.keenetic.com/explorer/kn-1613/en/16327-keeneticos-component-description.html)
