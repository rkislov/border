# PEAP и TTLS для 802.1X

Реализованы PEAPv0 с внутренним MS-CHAPv2 и EAP-TTLSv0 с PAP, TLS 1.2.
Метод выбирается явно в политике авторизации (`EAPMethod=peap|ttls`), источник —
local или directory. Политика доступа должна иметь назначение «Сеть», сегмент
и VLAN по расположению/NAS. Для набора политик используется протокол `eap`.
Допустимы основная проверка и проверка устройства; TOTP в этих методах пока
не поддерживается. Пустой EAPMethod сохраняет прежнее поведение.

Включите EAP в настройках тенанта, подготовьте CA и сертификат сервера.
Клиент обязан проверять доверенный CA и DNS-имя сервера. Внешний логин может
быть anonymous: разрешение, группы, VLAN и Class относятся к внутренней личности.
PEAP требует включённого MS-CHAPv2 у локального пользователя; для домена —
Samba/winbind helper и LDAP. TTLS проверяет пароль через обычный local/LDAP backend.
При выбранном туннельном методе обычный PAP не используется как запасной вход.

Пример настроек wpa_supplicant/eapol_test:

```
network={
 key_mgmt=IEEE8021X
 eap=PEAP
 identity="alice"
 anonymous_identity="anonymous"
 password="replace-me"
 ca_cert="/etc/border/ca.pem"
 domain_suffix_match="radius.example.org"
 phase1="tls_disable_tlsv1_3=1"
 phase2="auth=MSCHAPV2"
}
```

Для TTLS замените `eap=TTLS`, `phase2="auth=PAP"`.
Для Wi-Fi задайте SSID и `key_mgmt=WPA-EAP`; для проводного подключения
используйте wired-драйвер supplicant. Пример не содержит реальных секретов.

Ограничения: TLS resumption, PEAP cryptobinding, PEAPv1, TTLS внутренний EAP/CHAP
и TLS 1.3 пока не реализованы. Клиенты, требующие cryptobinding, не совместимы
с этой версией. Не отключайте проверку сертификата ради подключения.

Проверено независимым eapol_test 2.10 в Ubuntu ARM64: оба метода, фрагментация
128 байт, MPPE-ключи, неверный пароль, неверное имя TLS-сервера, блокировка
локального пользователя и истечение политики. Регрессия EAP-TLS также проходит.
Это проверка обмена RADIUS/EAP; физические точки доступа, коммутаторы и штатные
клиенты Windows ещё не проверены. Доменный backend переиспользован, но полный
доменный PEAP/TTLS обмен не включён в этот лабораторный прогон.

Спецификации: [RFC 5281](https://www.rfc-editor.org/rfc/rfc5281.html),
[MS-PEAP](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-peap/4043a26f-1cf1-4ba9-9282-d509decbd0a0).
