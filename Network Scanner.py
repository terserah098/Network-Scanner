import argparse
import json
import re
import subprocess
import sys
import textwrap
import time

AUTHOR_NAME = "Bayu"

def read_wifi_info():
    try:
        result = subprocess.run(
            ["netsh", "wlan", "show", "interfaces"],
            capture_output=True,
            text=True,
            check=False,
            timeout=10,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
        raise RuntimeError("Perintah netsh tidak tersedia atau waktu pemeriksaan habis.") from exc

    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip() or "Windows gagal membaca informasi Wi-Fi.")

    
    aliases = {
        "name": ("name", "nama"),
        "ssid": ("ssid",),
        "state": ("state", "status"),
        "authentication": ("authentication", "autentikasi", "authentifizierung"),
        "cipher": ("cipher", "sandi", "enkripsi", "chiffrement"),
    }
    info = {}
    for line in result.stdout.splitlines():
        if ":" not in line:
            continue
        label, value = (part.strip() for part in line.split(":", 1))
        normalized = label.casefold()
        for key, names in aliases.items():
            if normalized in names and value:
                info[key] = value

    if not info.get("ssid"):
        raise RuntimeError(
            "Tidak ditemukan jaringan Wi-Fi aktif. Pastikan Wi-Fi tersambung, "
            "lalu jalankan kembali skrip ini."
        )
    return info


def scan_nearby_networks():
    """Baca SSID dan tipe keamanan yang diumumkan jaringan di sekitar."""
    try:
        result = subprocess.run(
            ["netsh", "wlan", "show", "networks", "mode=bssid"],
            capture_output=True,
            text=True,
            check=False,
            timeout=15,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
        raise RuntimeError("Pemindaian Wi-Fi gagal atau melewati batas waktu.") from exc
    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip() or "Windows gagal membaca daftar Wi-Fi.")

    networks = []
    current = None
    for raw_line in result.stdout.splitlines():
        line = raw_line.strip()
        # SSID N : is emitted by netsh; ignore BSSID lines so device addresses
        # are not collected or shown.
        match = re.match(r"SSID\s+\d+\s*:\s*(.*)$", line, re.IGNORECASE)
        if match:
            if current:
                networks.append(current)
            current = {"ssid": match.group(1).strip() or "(SSID tersembunyi)"}
            continue
        if current and ":" in line:
            label, value = (part.strip() for part in line.split(":", 1))
            key = label.casefold()
            if key in ("authentication", "autentikasi"):
                current["authentication"] = value
            elif key in ("encryption", "enkripsi"):
                current["encryption"] = value
    if current:
        networks.append(current)
    return networks


def read_local_ip_info():
    """Baca IPv4 dan gateway lokal, utamakan interface Wi-Fi yang aktif."""
    command = (
        "$items = @(Get-NetIPConfiguration | Where-Object {"
        "$_.NetAdapter.Status -eq 'Up' -and $_.IPv4Address -and $_.IPv4DefaultGateway});"
        "$item = $items | Where-Object {$_.InterfaceAlias -match 'Wi-Fi|Wireless|WLAN'} | Select-Object -First 1;"
        "if (-not $item) {$item = $items | Select-Object -First 1};"
        "if ($item) {[pscustomobject]@{Interface=$item.InterfaceAlias;"
        "IPv4=$item.IPv4Address[0].IPAddress;Gateway=$item.IPv4DefaultGateway[0].NextHop} | ConvertTo-Json -Compress}"
    )
    try:
        result = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", command],
            capture_output=True,
            text=True,
            check=False,
            timeout=10,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return None
    if result.returncode != 0 or not result.stdout.strip():
        return None
    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError:
        return None


def recommendations(info):
    auth = info.get("authentication", "").casefold()
    cipher = info.get("cipher", "").casefold()
    tips = []

    if any(term in auth for term in ("open", "terbuka", "wep", "wpa ")):
        tips.append("Enkripsi terdeteksi terbuka atau usang. Atur router ke WPA3-Personal atau WPA2-AES.")
    elif "wpa3" in auth:
        tips.append("WPA3 terdeteksi. Gunakan kata sandi Wi-Fi yang panjang dan unik.")
    elif "wpa2" in auth:
        tips.append("WPA2 terdeteksi. Pastikan cipher memakai AES/CCMP dan gunakan kata sandi unik.")
    else:
        tips.append("Jenis autentikasi belum dapat dipastikan. Periksa pengaturan keamanan di halaman admin router.")

    if cipher and any(term in cipher for term in ("tkip", "wep")):
        tips.append("Cipher TKIP/WEP sudah usang. Ganti ke AES/CCMP melalui pengaturan router.")
    tips.extend((
        "Ganti kata sandi admin bawaan router dan perbarui firmware router.",
        "Nonaktifkan WPS jika tidak diperlukan; jangan membagikan kata sandi Wi-Fi utama kepada tamu.",
    ))
    return tips


def rating(info):
    auth = info.get("authentication", "").casefold()
    cipher = info.get("cipher", "").casefold()
    if "wpa3" in auth:
        return 95, "SANGAT BAIK", "\033[92m"
    if "wpa2" in auth and not any(term in cipher for term in ("tkip", "wep")):
        return 78, "CUKUP AMAN", "\033[96m"
    if any(term in auth for term in ("open", "terbuka", "wep")) or "tkip" in cipher:
        return 25, "PERLU PERHATIAN", "\033[91m"
    return 50, "BELUM DIKETAHUI", "\033[93m"


def show_dashboard(info):
    color_on = sys.stdout.isatty()
    reset = "\033[0m" if color_on else ""
    cyan = "\033[96m" if color_on else ""
    muted = "\033[90m" if color_on else ""
    score, label, status_color = rating(info)
    width = 66

    def line(content=""):
        print(f"  │ {content:<{width}} │")

    print()
    print(f"  ┌{'─' * (width + 2)}┐")
    line(f"{cyan}◈  WIFI GUARD{reset}                                               v1.1")
    line(f"{muted}   Pemeriksaan keamanan jaringan lokal{reset}")
    print(f"  ├{'─' * (width + 2)}┤")
    line("JARINGAN AKTIF")
    line(f"SSID           {info.get('ssid', 'tidak diketahui')}")
    line(f"Status         {info.get('state', 'tidak diketahui')}")
    line(f"Autentikasi    {info.get('authentication', 'tidak terbaca')}")
    line(f"Cipher         {info.get('cipher', 'tidak terbaca')}")
    print(f"  ├{'─' * (width + 2)}┤")
    blocks = round(score / 10)
    meter = "█" * blocks + "░" * (10 - blocks)
    line(f"SKOR KEAMANAN  {status_color}{score:>3}/100  {meter}  {label}{reset}")
    print(f"  ├{'─' * (width + 2)}┤")
    line("SARAN PENGAMANAN")
    for index, tip in enumerate(recommendations(info), 1):
        chunks = textwrap.wrap(tip, width=width - 5) or [""]
        line(f"{cyan}{index:>2}.{reset} {chunks[0]}")
        for chunk in chunks[1:]:
            line(f"    {chunk}")
    print(f"  ├{'─' * (width + 2)}┤")
    line(f"{muted}Hanya membaca info koneksi lokal. Tidak menguji sandi atau memindai jaringan.{reset}")
    print(f"  └{'─' * (width + 2)}┘")


def show_scan():
    try:
        networks = scan_nearby_networks()
    except RuntimeError as exc:
        print(f"\nTidak dapat memindai Wi-Fi: {exc}")
        return 1
    print("\nJARINGAN WI-FI DI SEKITAR (pemindaian pasif)")
    print("=" * 58)
    if not networks:
        print("Tidak ada jaringan yang terdeteksi.")
    for index, network in enumerate(networks, 1):
        print(f"{index:>2}. {network['ssid']}")
        print(f"    Keamanan : {network.get('authentication', 'tidak diketahui')}")
        if network.get("encryption"):
            print(f"    Enkripsi : {network['encryption']}")
    ip_info = read_local_ip_info()
    print("\nIP KONEKSI LOKAL")
    print("=" * 58)
    if ip_info:
        print(f"Interface : {ip_info.get('Interface', 'tidak diketahui')}")
        print(f"IPv4 lokal: {ip_info.get('IPv4', 'tidak diketahui')}")
        print(f"Gateway   : {ip_info.get('Gateway', 'tidak diketahui')}")
    else:
        print("IP lokal/gateway belum tersedia. Pastikan perangkat terhubung ke Wi-Fi.")
    print("\nHanya membaca siaran jaringan. Tidak mencoba kata sandi atau menghubungkan perangkat.")
    return 0


def show_cyber_menu():
    color_on = sys.stdout.isatty()
    cyan = "\033[96m" if color_on else ""
    green = "\033[92m" if color_on else ""
    yellow = "\033[93m" if color_on else ""
    muted = "\033[90m" if color_on else ""
    bold = "\033[1m" if color_on else ""
    reset = "\033[0m" if color_on else ""

    while True:
        print(f"\n  {cyan}{bold}WIFI GUARD{reset} {muted}:: LOCAL SECURITY CONSOLE{reset}")
        print(f"  {muted}WI-FI SECURITY CHECKER  |  {reset}{cyan}Dibuat oleh: {AUTHOR_NAME}{reset}")
        print(f"  {cyan}{'=' * 62}{reset}")
        print(f"  {green}●{reset} SYSTEM {green}{bold}ONLINE{reset}       {yellow}◆{reset} MODE {yellow}{bold}LOCAL CHECK{reset}")
        print(f"  {cyan}VERSION 1.1{reset}           {muted}WI-FI SECURITY CONSOLE{reset}")
        print(f"  {cyan}{'=' * 62}{reset}")
        print(f"\n  {cyan}+{'-' * 60}+{reset}")
        print(f"  {cyan}|{reset}{bold}{'MAIN MENU':^60}{reset}{cyan}|{reset}")
        print(f"  {cyan}|{reset}  {green}{bold}[01]{reset}  Periksa Wi-Fi yang sedang terhubung")
        print(f"  {cyan}|{reset}  {cyan}{bold}[02]{reset}  Pindai jaringan Wi-Fi di sekitar")
        print(f"  {cyan}|{reset}  {muted}[00]{reset}  Keluar")
        print(f"  {cyan}+{'-' * 60}+{reset}")
        print(f"\n  {muted}+-- SYSTEM LOG {'-' * 46}+{reset}")
        print(f"  {green}[OK]{reset}   Pemeriksa lokal siap")
        print(f"  {cyan}[INFO]{reset} Pemindaian pasif tersedia")
        print(f"  {yellow}[SAFE]{reset} Pemeriksaan baca-saja")
        try:
            choice = input(f"\n  {green}wifi-guard{reset}{cyan}@local{reset} {yellow}>{reset} ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\nSelesai.")
            return 0

        if choice in ("1", "01"):
            print(f"\n{muted}Membaca detail Wi-Fi aktif...{reset}")
            try:
                show_dashboard(read_wifi_info())
            except RuntimeError as exc:
                print(f"\nTidak dapat memeriksa Wi-Fi: {exc}")
        elif choice in ("2", "02"):
            print(f"\n{muted}Membaca siaran Wi-Fi di sekitar...{reset}")
            show_scan()
        elif choice in ("0", "00"):
            print("Selesai.")
            return 0
        else:
            print("Pilihan tidak valid. Gunakan 01, 02, atau 00.")


def show_menu():
    color_on = sys.stdout.isatty()
    cyan = "\033[96m" if color_on else ""
    green = "\033[92m" if color_on else ""
    yellow = "\033[93m" if color_on else ""
    muted = "\033[90m" if color_on else ""
    bold = "\033[1m" if color_on else ""
    reset = "\033[0m" if color_on else ""

    while True:
        print(f"\n{cyan}{bold}  WIFI GUARD{reset} {muted}/ PEMERIKSA KEAMANAN JARINGAN{reset}")
        print(f"  {cyan}Dibuat oleh: {AUTHOR_NAME}{reset}")
        print(f"  {muted}{'─' * 48}{reset}")
        print(f"  {bold}Pilih tindakan{reset}\n")
        print(f"  {green}{bold}1{reset}   Periksa jaringan yang sedang terhubung")
        print(f"  {cyan}{bold}2{reset}   Lihat jaringan Wi-Fi di sekitar")
        print(f"  {muted}0   Keluar{reset}\n")
        try:
            choice = input(f"  {yellow}>{reset} Pilihan {muted}[0-2]{reset}: ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\nSelesai.")
            return 0
        if choice == "1":
            print(f"\n{muted}Membaca detail Wi-Fi aktif...{reset}")
            try:
                show_dashboard(read_wifi_info())
            except RuntimeError as exc:
                print(f"\nTidak dapat memeriksa Wi-Fi: {exc}")
        elif choice == "2":
            print(f"\n{muted}Membaca siaran Wi-Fi di sekitar...{reset}")
            show_scan()
        elif choice == "0":
            print("Selesai.")
            return 0
        else:
            print("Pilihan tidak valid. Masukkan angka 0, 1, atau 2.")


def show_login_animation():
    """Animasi pembuka saja; tidak melakukan autentikasi akun."""
    interactive = sys.stdout.isatty()
    cyan = "\033[96m" if interactive else ""
    green = "\033[92m" if interactive else ""
    yellow = "\033[93m" if interactive else ""
    muted = "\033[90m" if interactive else ""
    bold = "\033[1m" if interactive else ""
    reset = "\033[0m" if interactive else ""

    font = {
        "A": ("01110", "10001", "11111", "10001", "10001"),
        "C": ("01111", "10000", "10000", "10000", "01111"),
        "E": ("11111", "10000", "11110", "10000", "11111"),
        "K": ("10001", "10010", "11100", "10010", "10001"),
        "N": ("10001", "11001", "10101", "10011", "10001"),
        "O": ("01110", "10001", "10001", "10001", "01110"),
        "R": ("11110", "10001", "11110", "10010", "10001"),
        "S": ("01111", "10000", "01110", "00001", "11110"),
        "T": ("11111", "00100", "00100", "00100", "00100"),
        "W": ("10001", "10001", "10101", "10101", "01010"),
    }

    def render_word(word):
        return [
            " ".join("".join("█" if pixel == "1" else " " for pixel in font[letter][row]) for letter in word)
            for row in range(5)
        ]

    logo = render_word("NETWORK") + [""] + render_word("SCANNER")
    panel_width = 56
    panel_lines = len(logo) + 4

    def draw_splash(frame, redraw=False, progress_visible=False):
        active = green if frame % 2 else cyan
        distorted = interactive and frame < 100 and frame % 2 == 1
        if redraw:
            rows_up = panel_lines + (1 if progress_visible else 0)
            sys.stdout.write(f"\033[{rows_up}A")
        rows = [f"  {cyan}╔{'═' * 8}◇{'═' * (panel_width - 9)}╗{reset}"]
        for row in logo:
            shown = row
            if distorted and "█" in shown:
                shown = shown[1:] + shown[:1]
            rows.append(f"  {cyan}║{reset}{active}{bold}{shown.center(panel_width)}{reset}{cyan}║{reset}")
        title = "WIFI GUARD // SIGNAL ERROR" if distorted else "WIFI GUARD"
        title_color = yellow if distorted else cyan
        rows.append(f"  {cyan}║{reset}{title_color}{bold}{title.center(panel_width)}{reset}{cyan}║{reset}")
        rows.append(f"  {cyan}║{reset}{muted}{'PEMERIKSA KEAMANAN WI-FI LOKAL'.center(panel_width)}{reset}{cyan}║{reset}")
        rows.append(f"  {cyan}╚{'═' * panel_width}╝{reset}")
        for line in rows:
            sys.stdout.write(("\033[2K" if redraw else "") + line + "\n")
        sys.stdout.flush()

    print()
    draw_splash(0)

    if not interactive:
        print("  Menyiapkan pemeriksa keamanan Wi-Fi... Siap.\n")
        return

    stages = [
        (0, 35, "Memuat antarmuka"),
        (36, 70, "Menyiapkan pemeriksaan lokal"),
        (71, 100, "Menyelesaikan persiapan"),
    ]
    width = 30
    spinner = "|/-\\"
    for percent in range(101):
        draw_splash(percent, redraw=True, progress_visible=percent > 0)
        if percent == 100:
            sys.stdout.write("\033[2K")
            sys.stdout.flush()
            break
        stage = next(label for start, end, label in stages if start <= percent <= end)
        filled = percent * width // 100
        bar = f"{green}{'#' * filled}{muted}{'.' * (width - filled)}{reset}"
        spin = cyan + spinner[percent % len(spinner)] + reset
        sys.stdout.write(f"\033[2K  {spin} {stage:<29} [{bar}] {percent:3d}%\n")
        sys.stdout.flush()
        time.sleep(0.018)
    print(f"\n\n  {green}{bold}>> SIAP DIGUNAKAN{reset}  {muted}Mode lokal aktif{reset}\n")


def main():
    show_login_animation()
    parser = argparse.ArgumentParser(description="Pemeriksaan Wi-Fi lokal yang bersifat baca-saja.")
    parser.add_argument(
        "--scan",
        action="store_true",
        help="tampilkan jaringan Wi-Fi yang disiarkan di sekitar beserta jenis keamanannya",
    )
    args = parser.parse_args()

    if not args.scan:
        return show_cyber_menu()

    if args.scan:
        try:
            networks = scan_nearby_networks()
        except RuntimeError as exc:
            print(f"\nTidak dapat memindai Wi-Fi: {exc}\n", file=sys.stderr)
            return 1
        print("\nJARINGAN WI-FI DI SEKITAR (pemindaian pasif)")
        print("=" * 58)
        if not networks:
            print("Tidak ada jaringan yang terdeteksi.")
        for index, network in enumerate(networks, 1):
            print(f"{index:>2}. {network['ssid']}")
            print(f"    Keamanan : {network.get('authentication', 'tidak diketahui')}")
            if network.get("encryption"):
                print(f"    Enkripsi : {network['encryption']}")
        print("\nHanya membaca siaran jaringan. Tidak mencoba kata sandi atau menghubungkan perangkat.")
        return 0

    try:
        info = read_wifi_info()
    except RuntimeError as exc:
        print(f"\n  ✖ Tidak dapat memeriksa Wi-Fi: {exc}\n", file=sys.stderr)
        return 1

    show_dashboard(info)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
