import os
import re
import requests
import time
from colorama import Fore, Style
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from collections import defaultdict


def get_online_serial_list(url):
    try:
        response = requests.get(url, headers={"Cache-Control": "no-cache"}, timeout=10)
        response.raise_for_status()
        data = response.json()
        entries = {}
        for serial, info in data.get("entries", {}).items():
            entries[serial.lower()] = {
                "status": info.get("status", "UNKNOWN"),
                "reason": info.get("reason", "UNSPECIFIED"),
            }
        return entries
    except Exception as e:
        print(f"Error downloading online Attestation list: {str(e)}")
        return {}


def process_certificate(cert_pem, online_serials):
    try:
        cert = x509.load_pem_x509_certificate(cert_pem.encode(), default_backend())

        hex_serial = format(cert.serial_number, "x").lower()
        hex_serial = hex_serial.lstrip("0")

        issuer_serial = None
        for attr in cert.issuer:
            if attr.oid == x509.NameOID.SERIAL_NUMBER:
                issuer_serial = re.sub(r"[^a-f0-9]", "", attr.value.lower())
                break

        status_info = None
        if hex_serial in online_serials:
            status_info = online_serials[hex_serial]
        elif issuer_serial and issuer_serial in online_serials:
            status_info = online_serials[issuer_serial]

        found = status_info is not None

        return hex_serial, issuer_serial, found, status_info

    except Exception as e:
        print(f"Certificate processing error: {str(e)}")
        return None, None, False, None


def main():
    ONLINE_LIST_URL = "https://android.googleapis.com/attestation/status?" + str(
        int(time.time())
    )
    SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))

    found_count = 0
    total_count = 0
    files_with_matches = defaultdict(list)
    files_to_delete = []

    print("\nDownloading online Attestation list...")
    online_serials = get_online_serial_list(ONLINE_LIST_URL)

    xml_files = [f for f in os.listdir(SCRIPT_DIR) if f.lower().endswith(".xml")]

    if not xml_files:
        print("\nNo XML files found in script directory")
        return

    for xml_file in xml_files:
        file_matches = 0
        total_count += 1
        print(f"\nProcessing {xml_file}...")
        with open(
            os.path.join(SCRIPT_DIR, xml_file), "r", encoding="utf-8", errors="ignore"
        ) as f:
            content = f.read().split("</CertificateChain>")[0]

        content = re.sub(r"<!--.*?-->", "", content, flags=re.DOTALL)

        certs = re.findall(
            r"(-----BEGIN CERTIFICATE.*?-----END CERTIFICATE.*?-----)",
            content,
            re.DOTALL,
        )

        if not certs:
            print("  No certificates found")
            continue

        for i, cert in enumerate(certs, 1):
            cert = cert.strip()
            hex_serial, issuer_serial, is_found, status_info = process_certificate(
                cert, online_serials
            )

            print(f"\n  Certificate {i}:")
            print(f"    Hex Serial: {hex_serial or 'N/A'}")
            print(f"    Issuer Serial: {issuer_serial or 'N/A'}")

            if is_found and status_info:
                status = status_info.get("status", "UNKNOWN")
                reason = status_info.get("reason", "UNSPECIFIED")
                print(f"    {Fore.RED}STATUS: {status}{Style.RESET_ALL}")
                print(f"    REASON: {reason}")

                if status == "REVOKED":
                    found_count += 1
                    file_matches += 1
                    files_with_matches[xml_file].append(
                        {
                            "cert_number": i,
                            "hex_serial": hex_serial,
                            "issuer_serial": issuer_serial,
                            "status": status,
                            "reason": reason,
                        }
                    )

        if file_matches:
            print(f"\n  Found {file_matches} matches in {xml_file}")
            files_to_delete.append(xml_file)

    print("\n\n=== FINAL RESULTS ===")
    print(f"Total number of keyboxes: {total_count}")
    print(
        f"Total number of valid keyboxes: {Fore.GREEN}{total_count - found_count}{Style.RESET_ALL}"
    )
    print(f"Total number of revoked keyboxes: {Fore.RED}{found_count}{Style.RESET_ALL}")

    if files_with_matches:
        print("\nKeyboxes containing matching serials:")
        for file_name, matches in files_with_matches.items():
            print(f"\n{file_name}:")
            for match in matches:
                print(f"  Certificate {match['cert_number']}:")
                print(f"    {Fore.RED}STATUS: {match['status']}{Style.RESET_ALL}")
                print(f"    REASON: {match['reason']}")

    if files_to_delete:
        print(f"\n\n=== FILES TO DELETE ===")
        for file_name in files_to_delete:
            print(f"  {Fore.RED}{file_name}{Style.RESET_ALL}")

        print(f"\nTotal files to delete: {len(files_to_delete)}")
        confirm = (
            input(
                f"\n{Fore.YELLOW}Do you want to delete these files? [Y/n]: {Style.RESET_ALL}"
            )
            .strip()
            .lower()
        )

        if confirm in ["", "y", "yes"]:
            print(f"\n=== DELETING REVOKED KEYBOXES ===")
            deleted_count = 0
            for file_name in files_to_delete:
                file_path = os.path.join(SCRIPT_DIR, file_name)
                try:
                    os.remove(file_path)
                    print(f"{Fore.RED}Deleted: {file_name}{Style.RESET_ALL}")
                    deleted_count += 1
                except Exception as e:
                    print(f"Error deleting {file_name}: {str(e)}")
            print(f"\nTotal files deleted: {deleted_count}")
        else:
            print(
                f"\n{Fore.YELLOW}Deletion cancelled. No files were deleted.{Style.RESET_ALL}"
            )


if __name__ == "__main__":
    try:
        import cryptography
    except ImportError:
        print("Error: cryptography package not installed. Install with:")
        print("pip install cryptography")
        exit(1)
    try:
        import colorama
    except ImportError:
        print("Error: colorama package not installed. Install with:")
        print("pip install colorama")
        exit(1)
    try:
        import requests
    except ImportError:
        print("Error: requests package not installed. Install with:")
        print("pip install requests")
        exit(1)
    main()
