import base64
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import spnego


HOST = "0.0.0.0"
PORT = 8080


def get_ntlm_message_type(token):
    # Тип NTLM-сообщения находится после сигнатуры NTLMSSP
    if len(token) < 12:
        return None

    if token[:8] != b"NTLMSSP\x00":
        return None

    return int.from_bytes(token[8:12], byteorder="little")


def print_ntlm_packet(direction, token):
    # Вывод информации о полученном или отправленном сообщении
    message_type = get_ntlm_message_type(token)

    type_names = {
        1: "NEGOTIATE",
        2: "CHALLENGE",
        3: "AUTHENTICATE",
    }

    type_name = type_names.get(message_type, "UNKNOWN")

    print()
    print("=" * 70)
    print(f"[{direction}] NTLM MESSAGE")
    print(f"Type   : {message_type} ({type_name})")
    print(f"Length : {len(token)} bytes")
    print(f"Base64 : {base64.b64encode(token).decode('ascii')}")
    print(f"HEX    : {token.hex()}")
    print("=" * 70)


class NTLMHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def setup(self):
        super().setup()
        self.auth_context = None

    def send_empty(self, status, authenticate=None):
        self.send_response(status)

        if authenticate:
            self.send_header("WWW-Authenticate", authenticate)

        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_GET(self):
        auth_header = self.headers.get("Authorization")

        # Первый запрос приходит без данных аутентификации
        if not auth_header:
            print()
            print(f"[+] Connection from {self.client_address[0]}")
            print("[+] NTLM authentication requested")

            self.send_empty(401, "NTLM")
            return

        if not auth_header.startswith("NTLM "):
            self.send_empty(401, "NTLM")
            return

        try:
            token = base64.b64decode(auth_header[5:])

            print_ntlm_packet("RECEIVED", token)

            # Создаем NTLM-контекст при первом сообщении клиента
            if self.auth_context is None:
                self.auth_context = spnego.server(protocol="ntlm")

            out_token = self.auth_context.step(token)

            # Если обмен еще не закончен, отправляем следующий токен
            if not self.auth_context.complete:
                if out_token:
                    print_ntlm_packet("SENT", out_token)

                    challenge = base64.b64encode(out_token).decode("ascii")
                    self.send_empty(401, f"NTLM {challenge}")
                else:
                    self.send_empty(401, "NTLM")

                return

            username = self.auth_context.client_principal or "unknown"

            print()
            print(f"[+] AUTHENTICATED: {username}")
            print()

            body = (
                "NTLM authentication successful\n"
                f"User: {username}\n"
            ).encode("utf-8")

            self.send_response(200)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        except Exception as exc:
            print()
            print(f"[-] Authentication failed: {exc}")

            self.auth_context = None
            self.send_empty(401, "NTLM")

    def log_message(self, format, *args):
        # Стандартный HTTP-лог здесь не нужен
        pass


def main():
    server = ThreadingHTTPServer((HOST, PORT), NTLMHandler)

    print("NTLM authentication server")
    print(f"Listening on http://{HOST}:{PORT}")
    print("Press Ctrl+C to stop")

    try:
        server.serve_forever()

    except KeyboardInterrupt:
        print("\nServer stopped.")

    finally:
        server.server_close()


if __name__ == "__main__":
    main()
