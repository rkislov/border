# Устойчивый стенд Border / UTM

`relay.py` переносит исходные RADIUS-пакеты через SSH без изменения подписей.
На Mac работает режим `local`, на сервере — `remote`. Каждому UDP-запросу
соответствует отдельный TCP-обмен с тайм-аутом; зависший запрос не блокирует
остальные. Число параллельных обработчиков ограничено 64. Неизвестные источники,
порты и некорректные размеры пакетов отбрасываются. Полезная нагрузка не логируется.

## Адреса лаборатории

- Mac host-only: `192.168.128.1`; CHR: `192.168.128.10`.
- Mac UDP 1812/1813 → SSH TCP 31812 → сервер RADIUS 127.0.0.1:1812/1813.
- Исходящий NAS-адрес серверного ретранслятора: `127.0.0.2`.
- Сервер UDP 127.0.0.2:3799 → обратный SSH TCP 37990 → CHR UDP 3799.
- Сервер TCP 127.0.0.1:38022 → обратный SSH → CHR SSH 22.

TCP-порты SSH-пробросов слушают только loopback. На сервере адаптируйте
`User`/пути в `border-lab-relay.service`, установите скрипт как
`/home/roman/border-lab/relay-supervised.py`, затем включите службу:

```sh
systemctl enable --now border-lab-relay
```

На Mac `install-launchd.py /private/path/supervision.json` устанавливает две
пользовательские службы: `ru.kislovs.border.lab-relay` и
`ru.kislovs.border.lab-tunnel`. Пример приватной конфигурации (chmod 600):

```json
{
  "directory": "/Users/USER/.local/share/border-lab",
  "python": "/opt/homebrew/bin/python3",
  "ssh": "/usr/bin/ssh",
  "proxy_command": "/private/path/ssh-via-edge %h %p",
  "destination": "USER@SERVER",
  "ssh_port": 22222,
  "local_address": "192.168.128.1",
  "router": "192.168.128.10"
}
```

Сначала проверьте ключи обоих SSH-серверов обычным входом. Туннель использует
`BatchMode`, строгую проверку host key, keepalive 10 секунд и перезапуск launchd
с интервалом не менее 10 секунд. Старые ручные ретрансляторы необходимо остановить
перед установкой, чтобы освободить порты. Установщик можно запускать повторно.

Это пользовательские LaunchAgents: нужен вход пользователя на Mac, работающий
UTM/CHR и доступный сетевой маршрут к серверу. После сна, восстановления сети
или перезапуска процесса службы переподключаются; не гарантируется доступность
лаборатории при выключенном Mac. Сертификаты/пароли и private JSON в Git не хранятся.

Проверка: принудительно завершить обе службы Mac через `launchctl kill SIGKILL`,
серверную — через `systemctl kill -s SIGKILL border-lab-relay`, убедиться в новых
PID/счётчике перезапуска и повторить RADIUS-вход. Проверка фрейминга:

```sh
python3 -m unittest discover -s deploy/lab -p 'test_*.py'
```

## Следующий физический NAS

Подготовлен [сценарий Netcraze Ultra](../../docs/NETCRAZE-LAB.md) с отдельными
SSID, сегментом и портом. Поддержка проводного authenticator, accounting и
Disconnect для WPA-Enterprise должна быть подтверждена на устройстве;
лабораторный эмулятор этого не доказывает.
