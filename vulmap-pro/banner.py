import socket
import re


def grab_banner(target, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2)

        sock.connect((target, port))

        if port in [80, 8080, 8000, 8008]:
            request = (
                b"HEAD / HTTP/1.1\r\n"
                b"Host: localhost\r\n"
                b"Connection: close\r\n\r\n"
            )

            sock.send(request)

        banner = sock.recv(2048).decode(errors="ignore").strip()

        sock.close()

        if banner:
            return banner

        return "No banner received"

    except Exception:
        return "Unable to retrieve banner"


def detect_software_version(banner):
    if not banner:
        return "Unknown", "Unknown"

    # Apache
    match = re.search(r"Apache/([\d.]+)", banner, re.IGNORECASE)

    if match:
        return "Apache", match.group(1)

    # nginx
    match = re.search(r"nginx/([\d.]+)", banner, re.IGNORECASE)

    if match:
        return "nginx", match.group(1)

    # Microsoft IIS
    match = re.search(r"Microsoft-IIS/([\d.]+)", banner, re.IGNORECASE)

    if match:
        return "Microsoft IIS", match.group(1)

    # OpenSSH
    match = re.search(r"OpenSSH[_/ ]([\d.p]+)", banner, re.IGNORECASE)

    if match:
        return "OpenSSH", match.group(1)

    return "Unknown", "Unknown"