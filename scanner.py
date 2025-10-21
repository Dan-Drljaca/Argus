#libs 
import socket
import nmap
import subprocess
import platform
import re
import string

def get_local_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
    except Exception:
        ip = "127.0.0.1"
    finally:
        s.close()
    return ip

def get_ssid():
    os_type = platform.system()
    if os_type == "Windows":
        try:
            ssid_output = subprocess.check_output(['netsh','wlan', 'show', 'interfaces'], text=True)
            match = re.search(r'SSID\s*:\s(.+)', ssid_output)
            return match.group(1).strip() if match else None
        except Exception:
            return None
    elif os_type == "Linux":
        try:
            ssid_output = subprocess.check_output(['nmcli', '-t', '-f', 'NAME,TYPE,DEVICE', 'connection', 'show', '--active'], text=True)
            wifi_line = next((line for line in ssid_output.splitlines() if ":wifi:" in line), None)
            return wifi_line.split(":")[0] if wifi_line else None
        except Exception:
            return None
    elif os_type == "Darwin":
        try:
            ssid_output = subprocess.check_output(
                ["/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport", "-I"],
                text=True
            )
            match = re.search(r'\s*SSID:\s(.+)', ssid_output)
            return match.group(1).strip() if match else None
        except Exception:
            return None
    return None

def scan_ports(ip=None, port_list='22,23,25,80,3389'):
    nm = nmap.PortScanner()
    ip = ip or get_local_ip()
    scan_result = {}

    try:
        # TCP Connect scan (works without admin/root)
        nm.scan(hosts=ip, ports=port_list, arguments='-sT')
    except nmap.PortScannerError as e:
        return {"error": f"Nmap scan failed: {e}"}
    except Exception as e:
        return {"error": f"Unexpected error: {e}"}

    for host in nm.all_hosts():
        host_info = {
            "hostname": nm[host].hostname(),
            "state": nm[host].state(),
            "protocols": {}
        }

        for proto in nm[host].all_protocols():
            ports = nm[host][proto].keys()
            host_info["protocols"][proto] = {
                port: nm[host][proto][port]['state'] if 'state' in nm[host][proto][port] else "unknown"
                for port in sorted(ports)
            }

        scan_result[host] = host_info

    return scan_result


def get_wifi_security():
    os_type = platform.system()

    if os_type == "Windows":
        try:
            result = subprocess.check_output(
                ['netsh', 'wlan', 'show', 'interfaces'],
                text=True
            )
            match = re.search(r'Authentication\s*:\s*(.+)', result, re.IGNORECASE)
            return match.group(1).strip() if match else None
        except subprocess.CalledProcessError:
            return None

    elif os_type == "Linux":
        try:
            interface = subprocess.check_output(
                ['nmcli', '-t', '-f', 'DEVICE,TYPE,STATE', 'device'],
                text=True
            )
            wifi_iface = next((line.split(':')[0] for line in interface.strip().split('\n') if ":wifi:connected" in line), None)

            if not wifi_iface:
                return None

            ssid_info = subprocess.check_output(['nmcli', '-t', '-f', 'ACTIVE,SSID', 'dev', 'wifi'], text=True)
            connected_ssid = next((line.split(':')[1] for line in ssid_info.strip().split('\n') if line.startswith("yes:")), None)

            wifi_info = subprocess.check_output(['nmcli', '-t', '-f', 'SSID,SECURITY', 'dev', 'wifi'], text=True)
            for line in wifi_info.strip().split('\n'):
                if connected_ssid in line:
                    return line.split(':')[1]
        except Exception:
            return None

    elif os_type == "Darwin":
        try:
            airport_cmd = "/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport"
            ssid_output = subprocess.check_output([airport_cmd, '-I'], text=True)
            security_output = subprocess.check_output([airport_cmd, '-s'], text=True)

            ssid_match = re.search(r'\s*SSID:\s(.+)', ssid_output)
            current_ssid = ssid_match.group(1).strip() if ssid_match else None

            for line in security_output.strip().split('\n'):
                if current_ssid and current_ssid in line:
                    return line.split()[-1]
        except Exception:
            return None

    return None


def get_wifi_password():
    os_type = platform.system()

    if os_type == "Windows":
        try:
            ssid_output = subprocess.check_output(['netsh', 'wlan', 'show', 'interfaces'], text=True)
            match = re.search(r'SSID\s*:\s(.+)', ssid_output)
            if not match:
                return None
            ssid = match.group(1).strip()

            profile_info = subprocess.check_output(['netsh', 'wlan', 'show', 'profile', ssid, 'key=clear'], text=True)
            key_match = re.search(r'Key Content\s*:\s(.+)', profile_info)
            return key_match.group(1).strip() if key_match else None
        except Exception:
            return None

    elif os_type == "Linux":
        try:
            ssid_output = subprocess.check_output(['nmcli', '-t', '-f', 'NAME,TYPE,DEVICE', 'connection', 'show', '--active'], text=True)
            wifi_line = next((line for line in ssid_output.splitlines() if ":wifi:" in line), None)
            if wifi_line:
                ssid = wifi_line.split(":")[0]
                passwd_info = subprocess.check_output(
                    ['nmcli', '-s', '-g', '802-11-wireless-security.psk', 'connection', 'show', ssid],
                    text=True
                ).strip()
                return passwd_info if passwd_info else None
        except Exception:
            return None

    elif os_type == "Darwin":
        try:
            ssid_output = subprocess.check_output(
                ["/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport", "-I"],
                text=True
            )
            ssid_match = re.search(r'\s*SSID:\s(.+)', ssid_output)
            if not ssid_match:
                return None
            ssid = ssid_match.group(1).strip()

            pw_output = subprocess.check_output(
                ['security', 'find-generic-password', '-D', 'AirPort network password', '-ga', ssid],
                stderr=subprocess.STDOUT,
                text=True
            )
            pw_match = re.search(r'password:\s*"(.+)"', pw_output)
            return pw_match.group(1) if pw_match else None
        except Exception:
            return None

    return None


def analyze_password_strength(password):
    if not password:
        return 0 
    length =len(password)
    score = 0
    #length scoring
    if length >= 12:
        score += 40
    elif length >= 8:
        score += 10
    #char variety
    if any(c.isupper() for c in password):
        score += 15
    if any(c.islower() for c in password):
        score += 15
    if any(c.isdigit() for c in password):
        score += 15
    if any(c in string.punctuation for c in password):
        score += 15
    return min(score, 100) #capping at 100 becasue anything over 100% is kinda stupid and would lead to a false sense of security


# For testing/debugging only
if __name__ == "__main__":
    print("Local IP:", get_local_ip())
    print("SSID", get_ssid())
    print("Port Scan:", scan_ports())
    print("Wi-Fi Security:", get_wifi_security())
    pwd = get_wifi_password()
    score = analyze_password_strength(pwd)
    print(f"Password Strength Score: {score}%")