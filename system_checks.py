#imports 
import platform
import subprocess
import re
def get_firewall_status():

    system = platform.system()

    try:
        # WINDOWS
        if system == "Windows":
            # The 'netsh' command manages network configurations
            result = subprocess.run(
                ["netsh", "advfirewall", "show", "allprofiles"],
                capture_output=True, text=True, shell=True
            )
            output = result.stdout.lower()

            # Look for specific phrases in output
            matches = re.findall(r"state\s*on|states\s*off", output)
            if any("on" in m for m in matches):
                return "Enabled"
            elif any("off" in m for m in matches):
                return "Disabled"
            else:
                return "Unknown"


        # LINUX
        elif system == "Linux":
            # Tries ufw (Ubuntu) or firewalld (CentOS/Fedora)
            result = subprocess.run(
                ["systemctl", "is-active", "ufw"],
                capture_output=True, text=True
            )
            output = result.stdout.lower()
            if "active" in output:
                return "Enabled"
            elif "inactive" in output:
                return "Disabled"
            else:
                # Try firewalld
                result = subprocess.run(
                    ["sudo", "systemctl", "is-active", "firewalld"],
                    capture_output=True, text=True
                )
                if "active" in result.stdout.lower():
                    return "Enabled"
                elif "inactive" in result.stdout.lower():
                    return "Disabled"
                else:
                    return "Unknown"
        
        #MacOs => babies first os 
        elif system == "Darwin":
            result = subprocess.run(
                ["/usr/libexec/ApplicationFirewall/socketfilterfw", "--getglobalstate"],
                capture_output=True, text=True
            )
            output = result.stdout.lower()
            if "enabled" in output:
                return "Enabled"
            elif "disabled" in output:
                return "Disabled"
            else:
                return "Unknown"
            
        else:
            return "Unsupported OS"
        
    except Exception as e:
        return f"error: {e}"
    
#Now we (me...sad) are now getting fully checking if remote access status
def get_remote_access_status():

    system = platform.system()

    try:
        #windows
        if system == "Windows":
            result = subprocess.run(
                ["reg", "query", "HKLM\\System\\CurrentControlSet\\Control\\Terminal Server", "/v", "fDenyTSConnections"],
                capture_output=True, text=True, shell=True
            )
            output = result.stdout.lower()
            # fDenyTSconnections = 0 menas remote desktop is allowed => Kinda bad 
            if "0x0" in output:
                return "Enabled"
            elif "0x1" in output:
                return "Disabled"
            else:
                return "Unknown"
            
        #linux
        elif system == "Linux":
            #check SSH daemon
            result = subprocess.run(
                ["systemctl", "is-active", "ssh"],
                capture_output=True, text=True
            )
            if "active" in result.stdout.lower():
                return "Enabled"
            elif "inactive" in result.stdout.lower():
                return "Disabled"
            else:
                return "Unknown"
        
        #macos
        elif system == "Darwin":
            result = subprocess.run(
                ["sudo", "systemsetup", "-getremotelogin"],
                capture_output=True, text=True
            )
            output = result.stdout.lower()
            if "on"in output:
                return "Enabled"
            elif "off" in output:
                return "Disbaled"
            else:
                return "Unknown"
        
        else:
            return "Unsupported OS"
        
    except Exception as e:
        return f"Error: {e}"
    
if __name__ == "__main__":
    print("=== Argus Net Protector - System Checks Debug ===\n")
    fw_status = get_firewall_status()
    remote_status = get_remote_access_status()

    print(f"Firewall Status: {fw_status}")
    print(f"Remote Access Status: {remote_status}")
