import base64
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import spnego


HOST = "0.0.0.0"
PORT = 8080


def get_ntlm_message_type(token):
    # Определяет тип NTLM-сообщения по полю MessageType
    if len(token) < 12:
        return None

    if token[:8] != b"NTLMSSP\x00":
        return None

    return int.from_bytes(token[8:12], byteorder="little")


def read_security_buffer(token, field_offset):
    # Читает Security Buffer и возвращает длину, смещение и данные поля
    if len(token) < field_offset + 8:
        raise ValueError("Security Buffer находится за пределами сообщения")

    length = int.from_bytes(
        token[field_offset:field_offset + 2],
        byteorder="little"
    )

    max_length = int.from_bytes(
        token[field_offset + 2:field_offset + 4],
        byteorder="little"
    )

    data_offset = int.from_bytes(
        token[field_offset + 4:field_offset + 8],
        byteorder="little"
    )

    if length == 0:
        return length, max_length, data_offset, b""

    if data_offset + length > len(token):
        raise ValueError(
            "Security Buffer указывает за пределы NTLM-сообщения"
        )

    data = token[data_offset:data_offset + length]

    return length, max_length, data_offset, data


def decode_ntlm_string(data, unicode_string=True):
    # Декодирует строковые поля NTLM
    if not data:
        return "<not supplied>"

    if unicode_string:
        return data.decode("utf-16le", errors="replace")

    return data.decode("cp437", errors="replace")


def parse_type1(token):
    # Разбирает NTLM NEGOTIATE_MESSAGE (Type 1)
    if len(token) < 32:
        raise ValueError("NTLM Type 1 message is too short")

    negotiation_flags = int.from_bytes(
        token[12:16],
        byteorder="little"
    )

    _, _, _, domain_data = read_security_buffer(token, 16)
    _, _, _, workstation_data = read_security_buffer(token, 24)

    domain = decode_ntlm_string(
        domain_data,
        unicode_string=False
    )

    workstation = decode_ntlm_string(
        workstation_data,
        unicode_string=False
    )

    print("Message type      : 1")
    print(f"Negotiation flags : 0x{negotiation_flags:08X}")
    print(f"Domain name       : {domain}")
    print(f"Workstation       : {workstation}")


def parse_target_info(data):
    # Разбирает AV_PAIR из поля Target Info
    av_names = {
        0: "MsvAvEOL",
        1: "NbComputerName",
        2: "NbDomainName",
        3: "DnsComputerName",
        4: "DnsDomainName",
        5: "DnsTreeName",
        6: "Flags",
        7: "Timestamp",
        8: "SingleHost",
        9: "TargetName",
        10: "ChannelBindings",
    }

    text_av_ids = {
        1,
        2,
        3,
        4,
        5,
        9,
    }

    position = 0

    while position + 4 <= len(data):
        av_id = int.from_bytes(
            data[position:position + 2],
            byteorder="little"
        )

        av_length = int.from_bytes(
            data[position + 2:position + 4],
            byteorder="little"
        )

        position += 4

        if position + av_length > len(data):
            print("  <invalid AV pair>")
            break

        value = data[position:position + av_length]
        position += av_length

        av_name = av_names.get(
            av_id,
            f"Unknown({av_id})"
        )

        if av_id == 0:
            print(f"  {av_name}")
            break

        if av_id in text_av_ids:
            decoded_value = value.decode(
                "utf-16le",
                errors="replace"
            )

        elif av_id == 6 and av_length == 4:
            flags = int.from_bytes(
                value,
                byteorder="little"
            )
            decoded_value = f"0x{flags:08X}"

        else:
            decoded_value = value.hex()

        print(f"  {av_name:<20}: {decoded_value}")


def parse_type2(token):
    # Разбирает NTLM CHALLENGE_MESSAGE (Type 2)
    if len(token) < 32:
        raise ValueError("NTLM Type 2 message is too short")

    _, _, _, target_name_data = read_security_buffer(
        token,
        12
    )

    negotiation_flags = int.from_bytes(
        token[20:24],
        byteorder="little"
    )

    server_challenge = token[24:32]

    use_unicode = bool(
        negotiation_flags & 0x00000001
    )

    target_name = decode_ntlm_string(
        target_name_data,
        unicode_string=use_unicode
    )

    print("Message type      : 2")
    print(f"Target name       : {target_name}")
    print(f"Server challenge  : {server_challenge.hex()}")
    print(f"Negotiation flags : 0x{negotiation_flags:08X}")

    print()
    print("Target info:")

    if len(token) >= 48:
        _, _, _, target_info_data = read_security_buffer(
            token,
            40
        )

        if target_info_data:
            parse_target_info(target_info_data)
        else:
            print("  <not supplied>")

    else:
        print("  <not supplied>")


def parse_type3(token):
    # Разбирает NTLM AUTHENTICATE_MESSAGE (Type 3)
    if len(token) < 64:
        raise ValueError("NTLM Type 3 message is too short")

    lm_length, _, lm_offset, _ = read_security_buffer(
        token,
        12
    )

    ntlm_length, _, ntlm_offset, ntlm_response = read_security_buffer(
        token,
        20
    )

    _, _, _, domain_data = read_security_buffer(
        token,
        28
    )

    _, _, _, username_data = read_security_buffer(
        token,
        36
    )

    _, _, _, workstation_data = read_security_buffer(
        token,
        44
    )

    negotiation_flags = int.from_bytes(
        token[60:64],
        byteorder="little"
    )

    use_unicode = bool(
        negotiation_flags & 0x00000001
    )

    domain = decode_ntlm_string(
        domain_data,
        unicode_string=use_unicode
    )

    username = decode_ntlm_string(
        username_data,
        unicode_string=use_unicode
    )

    workstation = decode_ntlm_string(
        workstation_data,
        unicode_string=use_unicode
    )

    print("Message type : 3")
    print(f"Username     : {username}")
    print(f"Domain       : {domain}")
    print(f"Workstation  : {workstation}")

    print()
    print("LM response:")
    print(f"  length = {lm_length}")
    print(f"  offset = {lm_offset}")

    print()
    print("NTLM response:")
    print(f"  length = {ntlm_length}")
    print(f"  offset = {ntlm_offset}")
    print(f"  data   = {ntlm_response.hex()}")


def print_ntlm_packet(direction, token):
    # Определяет тип сообщения и вызывает соответствующий парсер
    message_type = get_ntlm_message_type(token)

    type_names = {
        1: "NEGOTIATE",
        2: "CHALLENGE",
        3: "AUTHENTICATE",
    }

    type_name = type_names.get(
        message_type,
        "UNKNOWN"
    )

    print()
    print("=" * 70)
    print(f"[{direction}] NTLM {type_name}")
    print()

    try:
        if message_type == 1:
            parse_type1(token)

        elif message_type == 2:
            parse_type2(token)

        elif message_type == 3:
            parse_type3(token)

        else:
            print(
                f"Unknown NTLM message type: "
                f"{message_type}"
            )

    except ValueError as exc:
        print(f"Parse error: {exc}")

    print()
    print(f"Length : {len(token)} bytes")
    print(
        "Base64 : "
        + base64.b64encode(token).decode("ascii")
    )
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
            self.send_header(
                "WWW-Authenticate",
                authenticate
            )

        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_GET(self):
        auth_header = self.headers.get(
            "Authorization"
        )

        # Первый запрос клиента приходит без NTLM-токена
        if not auth_header:
            print()
            print(
                f"[+] Connection from "
                f"{self.client_address[0]}"
            )
            print(
                "[+] NTLM authentication requested"
            )

            self.send_empty(401, "NTLM")
            return

        if not auth_header.startswith("NTLM "):
            self.send_empty(401, "NTLM")
            return

        try:
            # Извлекаем NTLM-токен из HTTP-заголовка
            token = base64.b64decode(
                auth_header[5:]
            )

            print_ntlm_packet(
                "RECEIVED",
                token
            )

            if self.auth_context is None:
                self.auth_context = spnego.server(
                    protocol="ntlm"
                )

            # Передаем сообщение в NTLM-контекст
            out_token = self.auth_context.step(
                token
            )

            # Если обмен не завершен, отправляем клиенту следующий токен
            if not self.auth_context.complete:
                if out_token:
                    print_ntlm_packet(
                        "SENT",
                        out_token
                    )

                    challenge = base64.b64encode(
                        out_token
                    ).decode("ascii")

                    self.send_empty(
                        401,
                        f"NTLM {challenge}"
                    )

                else:
                    self.send_empty(
                        401,
                        "NTLM"
                    )

                return

            username = (
                self.auth_context.client_principal
                or "unknown"
            )

            print()
            print(
                f"[+] AUTHENTICATED: "
                f"{username}"
            )
            print()

            body = (
                "NTLM authentication successful\n"
                f"User: {username}\n"
            ).encode("utf-8")

            self.send_response(200)
            self.send_header(
                "Content-Type",
                "text/plain; charset=utf-8"
            )
            self.send_header(
                "Content-Length",
                str(len(body))
            )
            self.end_headers()
            self.wfile.write(body)

        except Exception as exc:
            print()
            print(
                f"[-] Authentication failed: "
                f"{exc}"
            )

            self.auth_context = None
            self.send_empty(
                401,
                "NTLM"
            )

    def log_message(self, format, *args):
        # Отключаем стандартный HTTP-лог
        pass


def main():
    server = ThreadingHTTPServer(
        (HOST, PORT),
        NTLMHandler
    )

    print("NTLM authentication server")
    print(
        f"Listening on "
        f"http://{HOST}:{PORT}"
    )
    print("Press Ctrl+C to stop")

    try:
        server.serve_forever()

    except KeyboardInterrupt:
        print("\nServer stopped.")

    finally:
        server.server_close()


if __name__ == "__main__":
    main()
