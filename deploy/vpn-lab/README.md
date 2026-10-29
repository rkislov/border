# Изолированная VPN-лаборатория

Два контейнера strongSwan в отдельной Docker-сети, без опубликованных портов
на хосте. Сервер использует Border на адресе Docker-шлюза `172.30.181.1`.
NAS в Border: `172.30.181.2`, словарь strongSwan, режим VPN, протокол привязки EAP.
Необходим Linux с IPsec/XFRM и Docker. Контейнеры получают только дополнительную
capability NET_ADMIN, без privileged/host networking.

В приватном каталоге подготовьте:

- `server/swanctl.conf` из примера, `server/private/server.key`,
  `server/x509/server.pem`, `server/x509ca/ca.pem`;
- `client/swanctl.conf` из примера и `client/x509ca/ca.pem`;
- `radius.conf` с общим секретом, `accounting_send_class=yes` и DAE, см.
  [описание VPN](../../docs/VPN-EAP-MSCHAPV2.md).

Сертификат сервера должен содержать SAN `vpn.lab.border.test`, клиент проверяет
это имя и CA. Пароли, сертификаты и ключи не помещайте в репозиторий.

```sh
BORDER_VPN_LAB_DIR=/private/path docker compose up -d --build
docker exec border-vpn-client swanctl --initiate --child net
docker exec border-vpn-client swanctl --list-sas
docker exec border-vpn-client ping -c 3 -I 10.181.0.10 10.181.0.1
docker exec border-vpn-client swanctl --terminate --ike lab
```

Проверьте фактически назначенный виртуальный IP через `swanctl --list-sas`;
при параллельных клиентах он может отличаться от первого адреса пула.
`start.sh` ожидает готовность VICI через реальный запрос, а не наличие socket-файла:
после перезапуска контейнера может остаться старый Unix socket.

После изменения тестового пользователя в приватном клиентском файле перезапустите
клиент, чтобы убрать прежние ключи и SA. Неверный пароль должен завершать обмен
EAP-Failure без установленного CHILD_SA. В Border проверьте Accounting Start/Stop,
привязку Class и отсутствие изменения сессий других пользователей.
