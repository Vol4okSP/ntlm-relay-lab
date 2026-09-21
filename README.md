# NTLM Authentication — разбор сообщений

## Статус

На данном этапе реализован сервис, который принимает штатную NTLM-аутентификацию от Windows-клиента, определяет тип каждого NTLM-сообщения, разбирает его основные поля и выводит полученные данные в терминал.

Для разбора сообщений реализованы отдельные функции:

```text
parse_type1(token)
parse_type2(token)
parse_type3(token)
```

После завершения обмена сервис также подтверждает успешную доменную аутентификацию пользователя.

## Суть NTLM-аутентификации

NTLM использует схему challenge-response. При аутентификации клиент и сервер проходят последовательность:

1. NTLM Type 1 — NEGOTIATE.
2. NTLM Type 2 — CHALLENGE.
3. NTLM Type 3 — AUTHENTICATE.

Сервис определяет тип сообщения с помощью функции:

```python
get_ntlm_message_type(token)
```

После определения типа вызывается соответствующая функция разбора.

Для Type 1 выводятся:

```text
Negotiation flags
Domain name
Workstation
```

Для Type 2:

```text
Target name
Server challenge
Negotiation flags
Target info
```

Для Type 3:

```text
Username
Domain
Workstation
LM response length
NTLM response length
NTLM response
```

Дополнительно для каждого сообщения выводятся его размер, Base64 и HEX-представление.

## Схема текущего этапа

```text
                    DOMAIN CONTROLLER
                           ^
                           |
                    authentication
                           |
Windows client --Type 1--> Python service
                           |
                     parse_type1()
                           |
Windows client <--Type 2--- Python service
                           |
                     parse_type2()
                           |
Windows client --Type 3--> Python service
                           |
                     parse_type3()
                           |
                           v
                     authenticated
```

## Стенд

Используются три виртуальные машины:

```text
DomainController
Windows Server 2022
192.168.56.10
practice.test

ProtocolServer
Windows Server 2022
192.168.56.20

ClientWorkstation
Windows 11
192.168.56.30
```

Все машины находятся в изолированной сети `192.168.56.0/24`.

## Требования

На `ProtocolServer`:

* Python 3.12;
* библиотека `pyspnego`.

Установка зависимости:

```powershell
python -m pip install pyspnego
```

## Запуск сервиса

На `ProtocolServer`:

```powershell
cd C:\NTLM-Lab
python auth_server.py
```

Ожидаемый вывод:

```text
NTLM authentication server
Listening on http://0.0.0.0:8080
Press Ctrl+C to stop
```

Для доступа клиента к сервису на стенде используется TCP-порт 8080.

Пример правила Windows Firewall:

```powershell
New-NetFirewallRule `
  -DisplayName "NTLM Lab TCP 8080" `
  -Direction Inbound `
  -Protocol TCP `
  -LocalPort 8080 `
  -RemoteAddress 192.168.56.0/24 `
  -Action Allow
```

## Проверка с клиента

На `ClientWorkstation`:

```powershell
Test-NetConnection 192.168.56.20 -Port 8080
```

При исправной связи:

```text
TcpTestSucceeded : True
```

Для запуска NTLM-аутентификации:

```powershell
curl.exe --ntlm -u "PRACTICE\labuser" http://192.168.56.20:8080/
```

Пароль вводится интерактивно после запроса `curl`.

## Пример успешной сессии (так же представлен в папке "screenshots")

Клиент:

```text
Enter host password for user 'PRACTICE\labuser':
NTLM authentication successful
User: PRACTICE\labuser
```

Сервер:

```text
[RECEIVED] NTLM NEGOTIATE

Message type      : 1
Negotiation flags : 0xA2088207
Domain name       : <not supplied>
Workstation       : <not supplied>

Length : 40 bytes
Base64 : <данные Type 1>
HEX    : <данные Type 1>


[SENT] NTLM CHALLENGE

Message type      : 2
Target name       : PRACTICE
Server challenge  : <challenge>
Negotiation flags : <flags>

Target info:
  NbDomainName       : PRACTICE
  NbComputerName     : PROTOCOLSRV
  DnsDomainName      : practice.test
  DnsComputerName    : PROTOCOLSRV.practice.test
  DnsTreeName        : practice.test

Length : <размер>
Base64 : <данные Type 2>
HEX    : <данные Type 2>


[RECEIVED] NTLM AUTHENTICATE

Message type : 3
Username     : labuser
Domain       : PRACTICE
Workstation  : CLIENTWIN11

LM response:
  length = 24
  offset = 140

NTLM response:
  length = <размер>
  offset = <смещение>
  data   = <NTLM response>

Length : <размер>
Base64 : <данные Type 3>
HEX    : <данные Type 3>

[+] AUTHENTICATED: PRACTICE\labuser
```

Полные значения Base64, HEX, Server Challenge и NTLM Response в README не приводятся, но сервис выводит их в терминал во время работы.

## Что делает код

`auth_server.py`:

* запускает HTTP-сервис на TCP-порту 8080;
* предлагает клиенту NTLM-аутентификацию;
* принимает NTLM Type 1 — NEGOTIATE;
* определяет тип NTLM-сообщения;
* разбирает Type 1 с помощью `parse_type1()`;
* формирует и отправляет NTLM Type 2 — CHALLENGE;
* разбирает Type 2 с помощью `parse_type2()`;
* отдельно разбирает AV-поля `Target Info`;
* принимает NTLM Type 3 — AUTHENTICATE;
* разбирает Type 3 с помощью `parse_type3()`;
* выводит имя пользователя, домен и рабочую станцию;
* выводит длину LM Response;
* выводит длину и содержимое NTLM Response;
* выводит размер, Base64 и HEX каждого NTLM-сообщения;
* завершает NTLM-аутентификацию через `pyspnego`;
* выводит имя успешно аутентифицированного пользователя.