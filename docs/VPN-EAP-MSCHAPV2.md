# VPN: IKEv2 и EAP-MSCHAPv2

Border реализует EAP type 26, проверку MS-CHAPv2 и выдачу ключей серверу VPN.
Сетевой VPN-туннель завершает strongSwan или совместимый шлюз; Border остаётся
RADIUS-сервером в одном Go-бинарнике. FreeRADIUS не используется.

## Политики Border

1. Настройте локального пользователя с включённой совместимостью MS-CHAPv2 или
   домен с LDAP/LDAPS и Samba/AD-помощником `BORDER_NTLM_AUTH`.
2. Создайте политику аутентификации с источником `local` или `directory` и шагом
   `primary`. Домен задаётся в этой политике. LDAP bind сам по себе не проверяет
   challenge-response; для домена нужен настроенный NTLM-помощник.
3. Создайте политику доступа с назначением `vpn`, допустимыми пользователями/
   группами, сроком действия и `SessionSeconds`.
4. Зарегистрируйте NAS со словарём `strongswan` и назначением `vpn`. Привяжите
   политику напрямую либо через набор политик с протоколом `eap`.
5. Для нескольких доменов используйте отдельные привязки и префикс
   `domain-id/login`; для локальных пользователей — `local/login`.
   Непрефиксированный логин проверяется источником выбранной политики.

Допускаются шаги `primary` и проверка зарегистрированного устройства `device`.
TOTP и другие несовместимые шаги дают отказ до проверки пароля. Сертификат
EAP-TLS остаётся отдельным методом для сетевого доступа. PEAP и TTLS здесь
не реализованы. Этот метод предназначен для IKEv2 с проверкой сертификата VPN-
сервера клиентом; не включайте его как открытый EAP-метод для Wi-Fi.

## strongSwan

Нужны плагины `eap-radius` на шлюзе и `eap-mschapv2` на клиенте. В Ubuntu 24.04
клиентский метод входит в `libcharon-extauth-plugins`. Dockerfile лаборатории
перечисляет нужные пакеты.

Фрагмент `/etc/strongswan.d/charon/eap-radius.conf` на шлюзе:

```ini
eap-radius {
  load = yes
  accounting = yes
  accounting_send_class = yes
  accounting_interval = 60
  dae {
    enable = yes
    listen = NAS_MANAGEMENT_IP
    port = 3799
    secret = REPLACE_WITH_SHARED_SECRET
  }
  servers {
    border {
      address = BORDER_IP
      secret = REPLACE_WITH_SHARED_SECRET
      sockets = 4
    }
  }
}
```

`accounting_send_class` обязателен для привязки accounting к разрешению Border
и автоматического отзыва. Без него события могут отображаться как не связанные
с политикой. Не включайте `class_group`: Border использует `Class` как непрозрачный
идентификатор выданного доступа, а не название группы.

В `swanctl.conf` шлюза задайте `local.auth=pubkey`, сертификат сервера,
`remote.auth=eap-radius`, `remote.eap_id=%any`, адресный пул и traffic selectors.
Клиент использует `local.auth=eap-mschapv2`, `local.eap_id`, пароль и
`remote.auth=pubkey` с точным `remote.id` и доверенным CA. Полный пример:
`deploy/vpn-lab/server.conf.example` и `client.conf.example`.

Для коротких лабораторных сессий явно задайте `over_time=30s`, `rand_time=0s`.
Запас времени strongSwan по умолчанию может оказаться больше выданного Border
Session-Timeout и вызвать немедленную повторную аутентификацию.

## Защита обмена и проверки

- `State` привязан к NAS, станции, порту, имени и снимку выбранной политики.
- Лимит — 256 диалогов на тенант, срок — 30 секунд; после истечения ключи очищаются.
- Повторные пакеты получают тот же ответ; ключи не выдаются до подтверждения
  клиентом AuthenticatorResponse.
- Перед Access-Accept повторно проверяются политика, срок, состояние пользователя
  и группы. Смена политики или блокировка во время диалога запрещает доступ.
- Ключи MPPE выводятся по RFC 3079 и защищаются RADIUS shared secret; открытые
  доменные пароли и NT-хеши домена не сохраняются.

Тесты: RFC 3079-вектор, успешный и отрицательные EAP-диалоги, подмена State/имени,
истечение состояния, повторные пакеты, изменение политики, блокировка, TOTP,
смешанные учётные данные и независимый `eapol_test` (включая проверку MPPE).

```sh
go test -race ./...
BORDER_EAPOL_TEST=/usr/bin/eapol_test go test ./internal/aaa -run TestEAPMSCHAPInteroperability -v
```

Основы протокола: [формат EAP-MSCHAPv2](https://www.ietf.org/archive/id/draft-kamath-pppext-eap-mschapv2-02.txt),
[RFC 2759](https://www.rfc-editor.org/rfc/rfc2759),
[RFC 3079](https://www.rfc-editor.org/rfc/rfc3079),
[strongSwan eap-radius](https://docs.strongswan.org/docs/latest/plugins/eap-radius.html).

## Проверенный стенд — 2026-10-29

Сборка `0.5.9-dev-vpn`; strongSwan 5.9.13 в двух контейнерах Ubuntu 24.04.
Порты IKE не опубликованы наружу. Samba AD работает в отдельном контейнере.

- `domain-test`: IKEv2/EAP-MSCHAPv2, проверка сертификата шлюза, успешное
  согласование MSK, установка CHILD_SA и 3/3 ICMP-пакета через IPsec.
- `local/chr-test`: отдельная VPN-политика, успешный CHILD_SA и 3/3 пакета.
- Неверный доменный пароль: EAP-Failure до Access-Accept, CHILD_SA отсутствует.
- Accounting Start/Stop содержит Class и связан с разрешением Border.
- Блокировка доменного пользователя в Samba: автоматический Disconnect-Request,
  подтверждённый Disconnect-ACK, IKE/CHILD_SA удалены. Пользователь включён обратно.
- Независимый eapol_test проверил правильный/неправильный пароль и MPPE-ключи.
- Перезапуск контейнеров проверен; клиент оставлен с корректной доменной
  конфигурацией без активного соединения. Сертификаты лаборатории действуют 30 дней.

IKEv2 на MikroTik и нативные VPN-клиенты Windows/macOS пока не проверены.
Это не PEAP/TTLS и не реализация TOTP поверх MS-CHAPv2.
