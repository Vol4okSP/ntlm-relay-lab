# NTLM Relay — промежуточный вариант

## Статус

Это промежуточная версия практического задания.

На текущем этапе реализован сервис, который принимает штатную NTLM-аутентификацию от Windows-клиента, выводит NTLM-сообщения в терминал и подтверждает успешную доменную аутентификацию.

Relay на другой сервис в этой версии еще не реализован.

## Суть NTLM Relay

NTLM использует схему challenge-response. В обычном случае клиент проходит последовательность:

1. NTLM Type 1 — NEGOTIATE.
2. NTLM Type 2 — CHALLENGE.
3. NTLM Type 3 — AUTHENTICATE.

При NTLM Relay промежуточный сервис не обязан знать пароль пользователя. Он передает сообщения NTLM между клиентом и целевым сервисом. Цель итоговой части задания — реализовать такую передачу в изолированном учебном стенде.

Текущая версия нужна для проверки первого этапа: сервис должен штатно принять настоящую NTLM-аутентификацию и показать обмен Type 1 → Type 2 → Type 3.

## Схема текущего этапа

```text
                    DOMAIN CONTROLLER
                           ^
                           |
                    authentication
                           |
Windows client --Type 1--> Python service
Windows client <--Type 2--- Python service
Windows client --Type 3--> Python service
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
cd C:\\NTLM-Lab
python auth\_server.py
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
curl.exe --ntlm -u "PRACTICE\\labuser" http://192.168.56.20:8080/
```

Пароль вводится интерактивно после запроса `curl`.

## Пример успешной сессии (так же представлен в папке "screenshots")

Клиент:

```text
Enter host password for user 'PRACTICE\\labuser':
NTLM authentication successful
User: PRACTICE\\labuser
```

Сервер:

```text
\[RECEIVED] NTLM MESSAGE
Type   : 1 (NEGOTIATE)
Length : 40 bytes
Base64 : <данные Type 1>
HEX    : <данные Type 1>

\[SENT] NTLM MESSAGE
Type   : 2 (CHALLENGE)
Length : <размер>
Base64 : <данные Type 2>
HEX    : <данные Type 2>

\[RECEIVED] NTLM MESSAGE
Type   : 3 (AUTHENTICATE)
Length : <размер>
Base64 : <данные Type 3>
HEX    : <данные Type 3>

\[+] AUTHENTICATED: PRACTICE\\labuser
```

Полные значения Base64/HEX в README не приводятся, но сервис выводит их в терминал во время работы.

## Что делает код

`auth\_server.py`:

* запускает HTTP-сервис на TCP 8080;
* предлагает клиенту NTLM-аутентификацию;
* принимает NTLM Type 1;
* формирует и отправляет NTLM Type 2;
* принимает NTLM Type 3;
* выводит тип, размер, Base64 и HEX каждого NTLM-сообщения;
* завершает аутентификацию через Windows SSPI;
* выводит имя успешно аутентифицированного пользователя.

