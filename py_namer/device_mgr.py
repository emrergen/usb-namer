import glob
import subprocess
import os
import re
from typing import Dict, List, Optional, Tuple

class DeviceManager:
    """
    Manages USB device detection and udev rule generation.
    Replicates functionality of namer.sh using Python.
    """

    def __init__(self):
        pass

    def run_command(self, cmd: List[str]) -> str:
        """Runs a shell command and returns stdout."""
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, check=True)
            return result.stdout.strip()
        except subprocess.CalledProcessError as e:
            print(f"Error running command {' '.join(cmd)}: {e}")
            return ""

    def list_potential_devices(self) -> List[str]:
        """Lists potential USB/Serial/Video devices from /dev."""
        patterns = [
            "/dev/ttyUSB*",
            "/dev/ttyACM*",
            "/dev/video*",
            "/dev/sd*" # Block devices, though less common for this use case
        ]
        devices = []
        for pattern in patterns:
            devices.extend(glob.glob(pattern))
        return sorted(devices)

    def get_device_info(self, device_path: str) -> Dict[str, str]:
        """
        Gathers detailed information about a device using udevadm.
        Returns a dictionary with keys: device, subsystem, vendor_id, product_id, serial, match_type, etc.
        """
        info = {
            "device": device_path,
            "name": os.path.basename(device_path),
            "subsystem": "",
            "vendor_id": "",
            "product_id": "",
            "serial": "",
            "match_type": "NONE",
            "model": "",
            "current_symlinks": ""
        }

        # Query Udev properties
        props_output = self.run_command(["udevadm", "info", "--name=" + device_path, "--query=property"])
        props = {}
        for line in props_output.splitlines():
            if "=" in line:
                key, value = line.split("=", 1)
                props[key] = value

        # Query existing symlinks
        symlinks_output = self.run_command(["udevadm", "info", "--query=symlink", "--name=" + device_path])
        links = symlinks_output.split()
        # Filter out standard system paths (by-id, by-path, by-uuid, etc)
        custom_links = []
        for link in links:
            if not any(x in link for x in ["by-id/", "by-path/", "by-uuid/", "by-partuuid/", "by-diskseq/"]):
                custom_links.append(link)
        info["current_symlinks"] = ", ".join(custom_links)


        # 1. Subsystem
        info["subsystem"] = props.get("SUBSYSTEM", "")
        
        # 2. Vendor/Product IDs
        info["vendor_id"] = props.get("ID_VENDOR_ID", "")
        info["product_id"] = props.get("ID_PRODUCT_ID", "")
        info["model"] = props.get("ID_MODEL", "Unknown Device")
        
        # Fallback: Attribute walk if missing
        if not info["vendor_id"] or not info["product_id"]:
            start_walk = False
            # udevadm info --attribute-walk --name=/dev/xyz
            walk_output = self.run_command(["udevadm", "info", "--attribute-walk", "--name=" + device_path])
            
            # Simple parser: look for the first occurrence of idVendor/idProduct in the chain
            # This mimics namer.sh logic: grep -m1
            v_match = re.search(r'ATTRS{idVendor}=="(.*?)"', walk_output)
            p_match = re.search(r'ATTRS{idProduct}=="(.*?)"', walk_output)
            
            if not info["vendor_id"] and v_match:
                info["vendor_id"] = v_match.group(1)
            if not info["product_id"] and p_match:
                info["product_id"] = p_match.group(1)

        # 3. Serial Number Strategy (Replicating namer.sh)
        # Priority: ID_SERIAL_SHORT > ID_SERIAL > ATTRS{serial}
        
        serial_short = props.get("ID_SERIAL_SHORT", "")
        serial_full = props.get("ID_SERIAL", "")
        
        if serial_short:
            info["serial"] = serial_short
            info["match_type"] = "ENV_SHORT"
        elif serial_full:
            info["serial"] = serial_full
            info["match_type"] = "ENV_FULL"
        else:
             # Try to get serial from attribute walk if not in ENV
             walk_output = self.run_command(["udevadm", "info", "--attribute-walk", "--name=" + device_path])
             # Find first ATTRS{serial} that is not a mac address or PCI ID (simple check)
             # namer.sh logic: /ATTRS{serial}==/{if(!found && device ~ /video|tty|usb/){print; found=1}}
             
             for line in walk_output.splitlines():
                 m = re.search(r'ATTRS{serial}=="(.*?)"', line)
                 if m:
                     candidate = m.group(1)
                     # Basic filter for obviously non-serial things (like PCI addresses 0000:00:1d.0)
                     if ":" in candidate and "." in candidate: 
                         continue
                     if candidate.count(":") > 3: # MAC address like
                         continue
                         
                     info["serial"] = candidate
                     info["match_type"] = "ATTRS"
                     break

        return info

    def generate_rule_content(self, device_info: Dict[str, str], symlink_name: str, use_fallback: bool = False) -> str:
        """Generates the content of the udev rule file."""
        
        subsystem = device_info.get("subsystem", "usb")
        vendor = device_info.get("vendor_id")
        product = device_info.get("product_id")
        serial = device_info.get("serial")
        match_type = device_info.get("match_type")
        device_path = device_info.get("device")
        
        # Group determination
        group = "plugdev"
        if subsystem == "tty":
            group = "dialout"
        elif subsystem == "video4linux" or subsystem == "video": # video4linux for exact match subsystem
             group = "video"
        
        # Clean symlink name
        symlink_name = re.sub(r'[^a-zA-Z0-9_-]', '', symlink_name)

        header = f"""# USB Device: {symlink_name}
# Created by: Python USB Namer
# Device: {device_path}
# Type: {subsystem}
"""

        rule_part = ""
        
        if serial and not use_fallback:
            header += f"# Match: {match_type}\n# Serial: {serial}\n\n"
            
            if match_type == "ENV_SHORT":
                match_key = 'ENV{ID_SERIAL_SHORT}'
            elif match_type == "ENV_FULL":
                match_key = 'ENV{ID_SERIAL}'
            else:
                match_key = 'ATTRS{serial}' # Fallback representation
            
            rule_part = f'SUBSYSTEM=="{subsystem}", ATTRS{{idVendor}}=="{vendor}", ATTRS{{idProduct}}=="{product}", {match_key}=="{serial}", MODE="0666", GROUP="{group}", SYMLINK+="{symlink_name}"'
            
        else:
            header += "# WARNING: No unique serial used - will match any device with same vendor/product ID\n\n"
            rule_part = f'SUBSYSTEM=="{subsystem}", ATTRS{{idVendor}}=="{vendor}", ATTRS{{idProduct}}=="{product}", MODE="0666", GROUP="{group}", SYMLINK+="{symlink_name}"'

        return header + rule_part + "\n"

    def write_rule_file(self, symlink_name: str, content: str) -> Tuple[bool, str]:
        """Writes the rule file to /etc/udev/rules.d/"""
        # Clean symlink name
        symlink_name = re.sub(r'[^a-zA-Z0-9_-]', '', symlink_name)
        filename = f"/etc/udev/rules.d/99-{symlink_name}.rules"
        
        try:
            if os.geteuid() != 0:
                return False, "Permission Denied: Must run as root to write rules."

            with open(filename, "w") as f:
                f.write(content)
            return True, f"Rule created at {filename}"
        except Exception as e:
            return False, str(e)

    def reload_udev(self) -> Tuple[bool, str]:
        """Reloads udev rules and triggers them."""
        if os.geteuid() != 0:
            return False, "Permission Denied: Must run as root to reload rules."
            
        try:
            self.run_command(["udevadm", "control", "--reload-rules"])
            self.run_command(["udevadm", "trigger"]) # Trigger all is safer to ensure it picks up
            return True, "Udev rules reloaded and triggered."
        except Exception as e:
            return False, f"Failed to reload rules: {e}"

    def delete_rule(self, symlink_name: str) -> Tuple[bool, str]:
        """Deletes the rule file associated with the symlink name."""
        symlink_name = re.sub(r'[^a-zA-Z0-9_-]', '', symlink_name) # Sanitize
        
        # Look for 99-{symlink_name}.rules or similar patterns
        # We enforce 99- prefix in creation, but lets be lenient in finding for deletion
        # actually, for safety, only delete what we created: 99-{name}.rules
        
        target = f"/etc/udev/rules.d/99-{symlink_name}.rules"
        
        if not os.path.exists(target):
             return False, f"Rule file not found: {target}"
             
        try:
            if os.geteuid() != 0:
                return False, "Permission Denied: Must run as root to delete rules."
                
            os.remove(target)
            return True, f"Deleted rule file: {target}"
        except Exception as e:
            return False, str(e)
