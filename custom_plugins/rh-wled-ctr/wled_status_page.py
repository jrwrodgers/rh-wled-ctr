'''WLED Status Webpage for RotorHazard'''
import logging
logger = logging.getLogger(__name__)
import requests
from requests.adapters import HTTPAdapter
from flask import Blueprint, jsonify, request
import socket
import json
import time
import platform
import ipaddress
from concurrent.futures import ThreadPoolExecutor, as_completed

# Import helper functions from main module
# These will be imported dynamically when setup_wled_routes is called
# to avoid circular import issues

# No-pool HTTP helpers to avoid urllib3 connection pool cleanup conflicting with gevent
def _session_no_pool():
    """Return a requests Session with connection pooling disabled (pool_maxsize=0)."""
    s = requests.Session()
    adapter = HTTPAdapter(pool_connections=0, pool_maxsize=0)
    s.mount("http://", adapter)
    s.mount("https://", adapter)
    return s


def _http_get_no_pool(url: str, timeout: float = 2) -> tuple:
    """GET without connection pooling. Returns (status_code, parsed_json or None). Closes connection."""
    session = _session_no_pool()
    response = None
    try:
        response = session.get(url, timeout=timeout, stream=False)
        data = response.json() if response.status_code == 200 else None
        return response.status_code, data
    except Exception:
        return (0, None)
    finally:
        if response is not None:
            try:
                response.close()
            except Exception:
                pass
        try:
            session.close()
        except Exception:
            pass


def _http_post_no_pool(url: str, json_payload: dict, timeout: float = 2) -> bool:
    """POST without connection pooling. Returns True on success. Closes connection."""
    session = _session_no_pool()
    response = None
    try:
        response = session.post(url, json=json_payload, timeout=timeout, stream=False)
        return response.status_code == 200
    except Exception:
        return False
    finally:
        if response is not None:
            try:
                response.close()
            except Exception:
                pass
        try:
            session.close()
        except Exception:
            pass


# Create Flask Blueprint for WLED status webpage
bp = Blueprint(
    "wled_status",
    __name__,
    static_folder="static",
    static_url_path="/rh-wled-ctr/static",
)


def check_device_status(ip: str) -> dict:
    """Check if WLED device is online and return its state."""
    try:
        url = f"http://{ip}/json"
        status_code, data = _http_get_no_pool(url, timeout=2)
        if status_code == 200 and data is not None:
            return {
                "online": True,
                "state": data,
                "error": None
            }
        return {
            "online": False,
            "state": None,
            "error": f"HTTP {status_code}" if status_code else "Connection error"
        }
    except Exception as e:
        logger.error(f"Unexpected error checking device {ip}: {e}")
        return {
            "online": False,
            "state": None,
            "error": f"Unexpected error: {str(e)}"
        }


def get_device_info(ip: str) -> dict:
    """Fetch device information from /json/info endpoint."""
    try:
        url = f"http://{ip}/json/info"
        status_code, info = _http_get_no_pool(url, timeout=2)
        if status_code == 200 and info is not None:
            version = info.get('ver', 'Unknown')
            led_count = info.get('leds', {}).get('count', 0)
            wifi_rssi = info.get('wifi', {}).get('rssi', None)
            battery_level = None
            battery_voltage = None
            
            u_field = info.get('u', {})
            if 'Battery level' in u_field:
                battery_level = u_field['Battery level'][0] if isinstance(u_field['Battery level'], list) else None
            if 'Battery voltage' in u_field:
                battery_voltage = u_field['Battery voltage'][0] if isinstance(u_field['Battery voltage'], list) else None
            
            return {
                "online": True,
                "version": version,
                "led_count": led_count,
                "wifi_rssi": wifi_rssi,
                "battery_level": battery_level,
                "battery_voltage": battery_voltage,
                "error": None
            }
        return {
            "online": False,
            "version": None,
            "led_count": None,
            "wifi_rssi": None,
            "battery_level": None,
            "battery_voltage": None,
            "error": f"HTTP {status_code}" if status_code else "Connection error"
        }
    except Exception as e:
        logger.error(f"Unexpected error getting device info for {ip}: {e}")
        return {
            "online": False,
            "version": None,
            "led_count": None,
            "wifi_rssi": None,
            "battery_level": None,
            "battery_voltage": None,
            "error": f"Unexpected error: {str(e)}"
        }


def organize_devices_by_group(devices_str: str) -> dict:
    """Organize devices by group number. Returns dict with group numbers as keys."""
    groups = {}
    if not devices_str or not isinstance(devices_str, str):
        return groups
    
    for entry in devices_str.split(","):
        entry = entry.strip()
        if not entry:
            continue
        
        if ":" in entry:
            group_str, ip = entry.split(":", 1)
            try:
                group = int(group_str.strip())
                ip = ip.strip()
            except ValueError:
                continue
        else:
            group = 1
            ip = entry
        
        if group not in groups:
            groups[group] = []
        groups[group].append(ip)
    
    return groups


def get_configured_ips(devices_str: str) -> set:
    """Extract all configured IP addresses from wled_devices string. Returns set of IPs."""
    configured_ips = set()
    if not devices_str or not isinstance(devices_str, str):
        return configured_ips
    
    for entry in devices_str.split(","):
        entry = entry.strip()
        if not entry:
            continue
        
        if ":" in entry:
            _, ip = entry.split(":", 1)
            ip = ip.strip()
        else:
            ip = entry.strip()
        
        if ip:
            configured_ips.add(ip)
    
    return configured_ips


def parse_descriptions(descriptions_str: str) -> dict:
    """Parse wled_device_descriptions string (JSON) into dict ip -> description."""
    if not descriptions_str or not isinstance(descriptions_str, str):
        return {}
    try:
        data = json.loads(descriptions_str)
        return data if isinstance(data, dict) else {}
    except (json.JSONDecodeError, TypeError):
        return {}


def build_descriptions_str(descriptions: dict) -> str:
    """Build wled_device_descriptions string from dict ip -> description."""
    if not descriptions:
        return ""
    return json.dumps(descriptions)


def get_network_range(preferred_prefix: str = "192") -> tuple:
    """Get network range (first_ip, last_ip) for network interface starting with preferred prefix."""
    try:
        # Get all network interfaces
        interfaces = []
        
        if platform.system() == "Windows":
            try:
                import subprocess
                result = subprocess.run(['ipconfig'], capture_output=True, text=True, timeout=5)
                logger.debug(f"Network interfaces:\n{result.stdout[:1000]}")
                
                # Parse ipconfig output for IPv4 addresses
                lines = result.stdout.split('\n')
                current_ip = None
                current_mask = None
                
                for i, line in enumerate(lines):
                    line_lower = line.lower()
                    # Look for IPv4 Address line
                    if ('ipv4 address' in line_lower or 'ip address' in line_lower) and ':' in line:
                        # Extract IP address
                        parts = line.split(':')
                        if len(parts) > 1:
                            ip_str = parts[1].strip().split()[0]
                            # Check if it starts with preferred prefix
                            if ip_str.startswith(preferred_prefix):
                                current_ip = ip_str
                                logger.info(f"Found preferred interface IP: {current_ip}")
                                # Reset mask when we find a new IP
                                current_mask = None
                    # Look for Subnet Mask line (should follow the IP address)
                    elif 'subnet mask' in line_lower and current_ip and ':' in line:
                        # Extract subnet mask
                        parts = line.split(':')
                        if len(parts) > 1:
                            current_mask = parts[1].strip().split()[0]
                            try:
                                network = ipaddress.IPv4Network(f"{current_ip}/{current_mask}", strict=False)
                                first_ip = str(list(network.hosts())[0]) if len(list(network.hosts())) > 0 else str(network.network_address + 1)
                                last_ip = str(network.broadcast_address - 1)
                                logger.info(f"Using network range: {first_ip} to {last_ip} for network {network} (IP: {current_ip}, Mask: {current_mask})")
                                return (first_ip, last_ip, current_ip)
                            except Exception as e:
                                logger.warning(f"Error calculating broadcast for {current_ip}/{current_mask}: {e}")
                                current_ip = None
                                current_mask = None
                    # Reset if we hit a new adapter section
                    elif line.strip().startswith('Ethernet adapter') or line.strip().startswith('Wireless LAN adapter'):
                        if current_ip and not current_mask:
                            # We had an IP but no mask, reset
                            current_ip = None
                            
            except Exception as e:
                logger.warning(f"Could not parse Windows network info: {e}", exc_info=True)
        else:
            # Linux/Mac - try netifaces if available, otherwise use ifconfig
            try:
                import netifaces
                for interface in netifaces.interfaces():
                    addrs = netifaces.ifaddresses(interface)
                    if netifaces.AF_INET in addrs:
                        for addr_info in addrs[netifaces.AF_INET]:
                            ip = addr_info.get('addr')
                            netmask = addr_info.get('netmask')
                            if ip and ip.startswith(preferred_prefix):
                                try:
                                    network = ipaddress.IPv4Network(f"{ip}/{netmask}", strict=False)
                                    first_ip = str(list(network.hosts())[0]) if len(list(network.hosts())) > 0 else str(network.network_address + 1)
                                    last_ip = str(network.broadcast_address - 1)
                                    logger.info(f"Found interface {interface}: IP={ip}, Range={first_ip} to {last_ip}")
                                    return (first_ip, last_ip, ip)
                                except Exception as e:
                                    logger.warning(f"Error calculating network range for {ip}/{netmask}: {e}")
            except ImportError:
                logger.debug("netifaces not available, trying ifconfig")
            except Exception as e:
                logger.debug(f"Error using netifaces: {e}")
            
            # Fallback to ifconfig parsing
            try:
                import subprocess
                result = subprocess.run(['ifconfig'], capture_output=True, text=True, timeout=5)
                logger.debug(f"Network interfaces:\n{result.stdout[:1000]}")
                # Parse ifconfig output (simplified - would need more robust parsing)
            except Exception as e:
                logger.debug(f"Could not get network info: {e}")
        
        # Fallback: try to get IPs from socket connections
        logger.info(f"Trying fallback method to find {preferred_prefix}.x.x.x interface...")
        test_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            # Connect to a test address to determine local interface
            test_socket.connect(('8.8.8.8', 80))
            local_ip = test_socket.getsockname()[0]
            test_socket.close()
            
            if local_ip.startswith(preferred_prefix):
                # Try common subnet masks
                for mask in ['255.255.255.0', '255.255.0.0']:
                    try:
                        network = ipaddress.IPv4Network(f"{local_ip}/{mask}", strict=False)
                        first_ip = str(list(network.hosts())[0]) if len(list(network.hosts())) > 0 else str(network.network_address + 1)
                        last_ip = str(network.broadcast_address - 1)
                        logger.info(f"Fallback: Using range {first_ip} to {last_ip} for {local_ip}/{mask}")
                        return (first_ip, last_ip, local_ip)
                    except:
                        continue
        except Exception as e:
            logger.warning(f"Fallback method failed: {e}")
        
        logger.warning(f"Could not find network interface starting with {preferred_prefix}")
        return (None, None, None)
        
    except Exception as e:
        logger.warning(f"Error getting network range: {e}")
        return (None, None, None)


def check_wled_device_http(ip: str, timeout: float = 1.0) -> dict:
    """Check if an IP address hosts a WLED device by checking /json/info endpoint."""
    try:
        url = f"http://{ip}/json/info"
        status_code, info = _http_get_no_pool(url, timeout=timeout)
        if status_code == 200 and info and ('ver' in info or 'leds' in info or 'name' in info):
            wifi_rssi = info.get('wifi', {}).get('rssi', None)
            device_info = {
                "ip": ip,
                "name": info.get("name", "WLED"),
                "version": info.get("ver", "Unknown"),
                "mac": info.get("mac", ""),
                "udpport": info.get("udpport", 21324),
                "wifi_rssi": wifi_rssi
            }
            logger.debug(f"Found WLED device at {ip}: {device_info['name']} v{device_info['version']}")
            return device_info
    except Exception as e:
        logger.debug(f"Error checking {ip}: {e}")
    return None


def scan_wled_devices(timeout: float = 1.0, max_workers: int = 20) -> list:
    """Scan network for WLED devices by checking HTTP /json/info endpoints concurrently."""
    found_devices = []
    
    logger.info(f"Starting WLED device HTTP scan with timeout={timeout}s, max_workers={max_workers}")
    
    # Get network range for preferred network (192.x.x.x)
    first_ip, last_ip, interface_ip = get_network_range("192")
    
    if not first_ip or not last_ip:
        logger.warning("Could not determine network range for 192.x.x.x, cannot scan")
        return found_devices
    
    if interface_ip:
        logger.info(f"Using network interface: {interface_ip}, scanning range: {first_ip} to {last_ip}")
    
    try:
        # Generate list of IPs to scan
        start_ip = ipaddress.IPv4Address(first_ip)
        end_ip = ipaddress.IPv4Address(last_ip)
        
        # Limit scan to reasonable range (max 254 IPs for /24 network)
        ip_list = []
        current = start_ip
        count = 0
        max_ips = 254  # Limit to /24 network
        
        while current <= end_ip and count < max_ips:
            ip_list.append(str(current))
            current += 1
            count += 1
        
        logger.info(f"Scanning {len(ip_list)} IP addresses from {first_ip} to {ip_list[-1]}")
        
        # Scan IPs concurrently
        start_time = time.time()
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            # Submit all scan tasks
            future_to_ip = {executor.submit(check_wled_device_http, ip, timeout): ip for ip in ip_list}
            
            # Collect results as they complete
            completed = 0
            for future in as_completed(future_to_ip):
                completed += 1
                ip = future_to_ip[future]
                try:
                    device_info = future.result()
                    if device_info:
                        found_devices.append(device_info)
                        logger.info(f"Found WLED device: {device_info['ip']} - {device_info['name']} v{device_info['version']}")
                except Exception as e:
                    logger.debug(f"Error checking {ip}: {e}")
                
                # Log progress every 50 IPs
                if completed % 50 == 0:
                    elapsed = time.time() - start_time
                    logger.debug(f"Scanned {completed}/{len(ip_list)} IPs in {elapsed:.2f}s, found {len(found_devices)} device(s)")
        
        elapsed_time = time.time() - start_time
        logger.info(f"WLED HTTP scan complete. Found {len(found_devices)} device(s) in {elapsed_time:.2f}s")
        logger.info(f"Scanned {len(ip_list)} IP addresses")
        
        if len(found_devices) == 0:
            logger.warning("No WLED devices found via HTTP scan. Possible reasons:")
            logger.warning("  - Devices not powered on or connected")
            logger.warning("  - Devices on different network segment")
            logger.warning("  - Firewall blocking HTTP port 80")
            logger.warning("  - Devices using non-standard ports")
        
    except Exception as e:
        logger.exception("Error during WLED device HTTP scan")
    
    return found_devices


def setup_wled_routes(rhapi):
    """Set up Flask routes for WLED status webpage."""
    # Import helper functions here to avoid circular imports
    from . import (
        get_ips_for_group,
        get_all_ips,
        build_wled_json_packet,
        _int_or_default
    )
    
    @bp.route("/wled_status")
    def wled_status_homepage():
        """Display WLED device status page."""
        try:
            devices_str = rhapi.db.option("wled_devices") or ""
            descriptions_str = rhapi.db.option("wled_device_descriptions") or ""
            groups = organize_devices_by_group(devices_str)
            descriptions = parse_descriptions(descriptions_str)
            
            html = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>WLED Device Status</title>
    <link rel="stylesheet" href="/static/rotorhazard.css">
    <style>
        table {
            width: 100%;
            border-collapse: collapse;
            margin: 20px 0;
        }
        th, td {
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid #ddd;
        }
        th {
            background-color: #007bff;
            color: white;
            font-weight: bold;
        }
        .status-online {
            color: #28a745;
            font-weight: bold;
        }
        .status-offline {
            color: #dc3545;
            font-weight: bold;
        }
        .battery-low-amber {
            color: #d97706;
        }
        .battery-low-red {
            color: #dc3545;
        }
        .battery-critical {
            color: #dc3545;
            font-weight: bold;
        }
        .test-button {
            padding: 5px 15px;
            background-color: #007bff;
            color: white;
            border: none;
            border-radius: 3px;
            cursor: pointer;
            margin-right: 5px;
        }
        .test-button:hover {
            background-color: #0056b3;
        }
        .settings-button {
            padding: 5px 15px;
            background-color: #6c757d;
            color: white;
            border: none;
            border-radius: 3px;
            cursor: pointer;
            margin-right: 5px;
            text-decoration: none;
            font-size: inherit;
            display: inline-block;
        }
        .settings-button:hover {
            background-color: #5a6268;
            color: white;
        }
        .refresh-button {
            margin: 20px 0;
            padding: 10px 20px;
            background-color: #28a745;
            color: white;
            border: none;
            border-radius: 3px;
            cursor: pointer;
            font-size: 16px;
        }
        .refresh-button:hover {
            background-color: #218838;
        }
        .scan-button {
            margin: 20px 0;
            padding: 10px 20px;
            background-color: #17a2b8;
            color: white;
            border: none;
            border-radius: 3px;
            cursor: pointer;
            font-size: 16px;
        }
        .scan-button:hover {
            background-color: #138496;
        }
        .scan-button:disabled {
            background-color: #6c757d;
            cursor: not-allowed;
        }
        .scan-results-list {
            margin-top: 15px;
            padding: 15px;
            border: 1px solid #ddd;
            border-radius: 4px;
            background-color: #f8f9fa;
        }
        .scan-result-item {
            padding: 8px 10px;
            margin: 3px 0;
            border-bottom: 1px solid #ddd;
            display: flex;
            justify-content: space-between;
            align-items: center;
            white-space: nowrap;
        }
        .scan-result-item:last-child {
            border-bottom: none;
        }
        .scan-result-info {
            flex: 1;
            overflow: hidden;
            text-overflow: ellipsis;
        }
        .add-device-button {
            padding: 5px 12px;
            background-color: #28a745;
            color: white;
            border: none;
            border-radius: 3px;
            cursor: pointer;
            font-size: 16px;
            font-weight: bold;
            margin-left: 10px;
            min-width: 30px;
        }
        .add-device-button:hover {
            background-color: #218838;
        }
        .add-device-button:disabled {
            background-color: #6c757d;
            cursor: not-allowed;
        }
        .editable-group, .editable-desc {
            width: 100%;
            max-width: 80px;
            padding: 6px 8px;
            border: 1px solid #ccc;
            border-radius: 3px;
            font-size: 14px;
            box-sizing: border-box;
        }
        .editable-desc {
            max-width: 180px;
        }
        .editable-group:focus, .editable-desc:focus {
            border-color: #007bff;
            outline: none;
        }
        .test-button.stop {
            background-color: #dc3545;
        }
        .test-button.stop:hover {
            background-color: #c82333;
        }
        .no-data {
            color: #999;
            font-style: italic;
        }
    </style>
</head>
<body>
    <div class="container-fluid">
        <h1>WLED Device Status</h1>
        <button class="refresh-button" onclick="refreshPage()">Refresh Device Status</button>
"""
            
            if not groups:
                html += '<p>No WLED devices configured. Configure devices in Settings → WLED Setup.</p>'
            else:
                # Collect all devices with their group numbers and descriptions
                device_list = []
                sorted_groups = sorted(groups.keys())
                for group in sorted_groups:
                    for ip in groups[group]:
                        device_info = get_device_info(ip)
                        device_list.append({
                            "group": group,
                            "ip": ip,
                            "description": descriptions.get(ip, ""),
                            "info": device_info
                        })
                
                # Generate table
                html += '<table>'
                html += '<thead><tr>'
                html += '<th>Group</th>'
                html += '<th>Description</th>'
                html += '<th>IP Address</th>'
                html += '<th>Online</th>'
                html += '<th>Version</th>'
                html += '<th>LED Count</th>'
                html += '<th>WiFi RSSI</th>'
                html += '<th>Battery Level</th>'
                html += '<th>Battery Voltage</th>'
                html += '<th>Actions</th>'
                html += '</tr></thead>'
                html += '<tbody>'
                
                for device in device_list:
                    info = device["info"]
                    online_class = "status-online" if info["online"] else "status-offline"
                    online_text = "Yes" if info["online"] else f"No ({info['error']})"
                    
                    version = info["version"] if info["version"] else '<span class="no-data">N/A</span>'
                    led_count = info["led_count"] if info["led_count"] is not None else '<span class="no-data">N/A</span>'
                    wifi_rssi = f"{info['wifi_rssi']} dBm" if info["wifi_rssi"] is not None else '<span class="no-data">N/A</span>'
                    # Battery level with color: <10% bold red, <20% red, <30% amber
                    bl = info["battery_level"]
                    if bl is not None:
                        try:
                            pct = int(bl) if isinstance(bl, (int, float)) else int(float(bl))
                            if pct < 10:
                                battery_level = f'<span class="battery-critical">{pct}%</span>'
                            elif pct < 20:
                                battery_level = f'<span class="battery-low-red">{pct}%</span>'
                            elif pct < 30:
                                battery_level = f'<span class="battery-low-amber">{pct}%</span>'
                            else:
                                battery_level = f"{pct}%"
                        except (TypeError, ValueError):
                            battery_level = f"{bl}%"
                    else:
                        battery_level = '<span class="no-data">N/A</span>'
                    battery_voltage = f"{info['battery_voltage']} V" if info["battery_voltage"] is not None else '<span class="no-data">N/A</span>'
                    
                    # Escape description for HTML attribute
                    desc_attr = device["description"].replace("&", "&amp;").replace('"', "&quot;").replace("<", "&lt;").replace(">", "&gt;")
                    ip_attr = device["ip"].replace(".", "-")
                    
                    html += f'<tr>'
                    html += f'<td><input type="number" class="editable-group" min="1" value="{device["group"]}" data-ip="{ip_attr}" data-ip-raw="{device["ip"]}" /></td>'
                    html += f'<td><input type="text" class="editable-desc" value="{desc_attr}" data-ip="{ip_attr}" data-ip-raw="{device["ip"]}" placeholder="Description" /></td>'
                    html += f'<td>{device["ip"]}</td>'
                    html += f'<td class="{online_class}">{online_text}</td>'
                    html += f'<td>{version}</td>'
                    html += f'<td>{led_count}</td>'
                    html += f'<td>{wifi_rssi}</td>'
                    html += f'<td>{battery_level}</td>'
                    html += f'<td>{battery_voltage}</td>'
                    settings_url = f"http://{device['ip']}/settings"
                    html += f'<td><button id="test-btn-{ip_attr}" class="test-button" onclick="toggleTestDevice(\'{device["ip"]}\')">Test</button> '
                    html += f'<a href="{settings_url}" target="_blank" rel="noopener noreferrer" class="settings-button">Settings</a></td>'
                    html += f'</tr>'
                
                html += '</tbody></table>'
            
            html += """
        <button id="scan-button" class="scan-button" onclick="scanDevices(this)">Scan WLED Devices</button>
        <div id="scan-results" style="margin-top: 20px;"></div>
    </div>
    <script>
        const testStates = {};
        
        // Define scanDevices function - make it globally available
        window.scanDevices = function(button) {
            console.log('scanDevices called', button);
            if (!button) {
                console.error('Button parameter is missing');
                return;
            }
            const resultsDiv = document.getElementById('scan-results');
            if (!resultsDiv) {
                console.error('scan-results div not found');
                alert('Error: Could not find results container');
                return;
            }
            
            button.disabled = true;
            button.textContent = 'Scanning...';
            resultsDiv.innerHTML = '<p>Scanning network for WLED devices...</p>';
            
            console.log('Sending scan request to /wled_status/scan');
            fetch('/wled_status/scan', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                }
            })
            .then(response => {
                console.log('Response status:', response.status);
                if (!response.ok) {
                    throw new Error('HTTP ' + response.status + ': ' + response.statusText);
                }
                return response.json();
            })
            .then(data => {
                console.log('Scan response:', data);
                button.disabled = false;
                button.textContent = 'Scan WLED Devices';
                
                if (data.success && data.devices && data.devices.length > 0) {
                    // Clear previous results
                    resultsDiv.innerHTML = '';
                    
                    // Create table
                    const table = document.createElement('table');
                    
                    // Create table header
                    const thead = document.createElement('thead');
                    const headerRow = document.createElement('tr');
                    ['IP Address', 'Version', 'WiFi RSSI', 'Actions'].forEach(function(headerText) {
                        const th = document.createElement('th');
                        th.textContent = headerText;
                        headerRow.appendChild(th);
                    });
                    thead.appendChild(headerRow);
                    table.appendChild(thead);
                    
                    // Create table body
                    const tbody = document.createElement('tbody');
                    
                    // Create rows for each device
                    data.devices.forEach(function(device) {
                        const row = document.createElement('tr');
                        
                        // IP Address column
                        const ipCell = document.createElement('td');
                        ipCell.textContent = device.ip || '';
                        row.appendChild(ipCell);
                        
                        // Version column
                        const versionCell = document.createElement('td');
                        versionCell.textContent = device.version || 'Unknown';
                        row.appendChild(versionCell);
                        
                        // WiFi RSSI column
                        const rssiCell = document.createElement('td');
                        if (device.wifi_rssi !== null && device.wifi_rssi !== undefined) {
                            rssiCell.textContent = device.wifi_rssi + ' dBm';
                        } else {
                            const span = document.createElement('span');
                            span.className = 'no-data';
                            span.textContent = 'N/A';
                            rssiCell.appendChild(span);
                        }
                        row.appendChild(rssiCell);
                        
                        // Actions column with Add button
                        const actionsCell = document.createElement('td');
                        const addButton = document.createElement('button');
                        addButton.className = 'add-device-button';
                        addButton.textContent = '+';
                        addButton.title = 'Add to WLED devices';
                        addButton.addEventListener('click', function() {
                            addDevice(device.ip, this);
                        });
                        actionsCell.appendChild(addButton);
                        row.appendChild(actionsCell);
                        
                        tbody.appendChild(row);
                    });
                    
                    table.appendChild(tbody);
                    resultsDiv.appendChild(table);
                } else {
                    let message = '<p style="font-size: 16px;">No WLED devices found on the network.</p>';
                    if (data.message) {
                        message += '<p style="font-size: 16px; color: #666;">' + data.message + '</p>';
                    }
                    message += '<p style="font-size: 16px; color: #666;">Check RotorHazard server logs for detailed scan information.</p>';
                    resultsDiv.innerHTML = message;
                }
            })
            .catch(error => {
                console.error('Scan error:', error);
                button.disabled = false;
                button.textContent = 'Scan WLED Devices';
                resultsDiv.innerHTML = '<p style="color: #dc3545;">Error scanning network: ' + error + '</p>';
            });
        };
        
        // Define addDevice function - make it globally available
        window.addDevice = function(ip, button) {
            button.disabled = true;
            button.textContent = '...';
            
            fetch('/wled_status/add_device/' + encodeURIComponent(ip), {
                method: 'POST'
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    button.textContent = '✓';
                    button.style.backgroundColor = '#28a745';
                    // Refresh the page after a short delay to show the new device in the table
                    setTimeout(function() {
                        window.location.reload();
                    }, 1000);
                } else {
                    alert(data.message || 'Failed to add device');
                    button.disabled = false;
                    button.textContent = '+';
                }
            })
            .catch(error => {
                alert('Error adding device: ' + error);
                button.disabled = false;
                button.textContent = '+';
            });
        };
        
        function refreshPage() {
            window.location.reload();
        }
        
        // Save group when user changes the Group input
        document.addEventListener('change', function(e) {
            if (e.target.classList.contains('editable-group')) {
                var input = e.target;
                var ip = input.getAttribute('data-ip-raw');
                var newGroup = parseInt(input.value, 10) || 1;
                if (newGroup < 1) { newGroup = 1; input.value = 1; }
                
                fetch('/wled_status/update_group', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ ip: ip, new_group: newGroup })
                })
                .then(function(response) { return response.json(); })
                .then(function(data) {
                    if (data.success) {
                        if (typeof data.message !== 'undefined') { /* optional notify */ }
                    } else {
                        alert(data.message || 'Failed to update group');
                    }
                })
                .catch(function(err) { alert('Error: ' + err); });
            }
            if (e.target.classList.contains('editable-desc')) {
                var input = e.target;
                var ip = input.getAttribute('data-ip-raw');
                var description = input.value;
                
                fetch('/wled_status/update_description', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ ip: ip, description: description })
                })
                .then(function(response) { return response.json(); })
                .then(function(data) {
                    if (!data.success) {
                        alert(data.message || 'Failed to update description');
                    }
                })
                .catch(function(err) { alert('Error: ' + err); });
            }
        });
        
        function toggleTestDevice(ip) {
            const buttonId = 'test-btn-' + ip.replace(/\\./g, '-');
            const button = document.getElementById(buttonId);
            const isTesting = testStates[ip] || false;
            
            if (isTesting) {
                // Stop test
                fetch('/wled_status/stop/device/' + encodeURIComponent(ip), {
                    method: 'POST'
                })
                .then(response => response.json())
                .then(data => {
                    testStates[ip] = false;
                    button.textContent = 'Test';
                    button.classList.remove('stop');
                })
                .catch(error => {
                    console.error('Error stopping test: ' + error);
                });
            } else {
                // Start test
                fetch('/wled_status/test/device/' + encodeURIComponent(ip), {
                    method: 'POST'
                })
                .then(response => response.json())
                .then(data => {
                    if (data.success) {
                        testStates[ip] = true;
                        button.textContent = 'Stop';
                        button.classList.add('stop');
                    } else {
                        alert(data.message || 'Test failed');
                    }
                })
                .catch(error => {
                    alert('Error: ' + error);
                });
            }
        }
    </script>
</body>
</html>"""
            
            return html
        except Exception as e:
            logger.exception("Error in wled_status_homepage")
            return f"""<html><body>
                <h2>Error loading WLED status</h2>
                <p>{str(e)}</p>
            </body></html>"""
    
    @bp.route("/wled_status/test/device/<ip>", methods=["POST"])
    def test_device(ip: str):
        """Test a single WLED device."""
        try:
            payload = build_wled_json_packet(
                color=(0, 255, 0), mode=1, speed=128, intensity=128, power=1
            )
            url = f"http://{ip}/json/state"
            ok = _http_post_no_pool(url, payload, timeout=2)
            if ok:
                logger.info(f"Test command sent to device {ip}")
                return jsonify({"success": True, "message": f"Test command sent to {ip}"})
            return jsonify({"success": False, "message": "Test request failed"}), 500
        except Exception as e:
            logger.exception(f"Unexpected error testing device {ip}")
            return jsonify({"success": False, "message": f"Unexpected error: {str(e)}"}), 500
    
    @bp.route("/wled_status/stop/device/<ip>", methods=["POST"])
    def stop_device(ip: str):
        """Stop test on a single WLED device (turn off)."""
        try:
            payload = {"on": False}
            url = f"http://{ip}/json/state"
            ok = _http_post_no_pool(url, payload, timeout=2)
            if ok:
                logger.info(f"Stop command sent to device {ip}")
                return jsonify({"success": True, "message": f"Test stopped on {ip}"})
            return jsonify({"success": False, "message": "Stop request failed"}), 500
        except Exception as e:
            logger.exception(f"Unexpected error stopping device {ip}")
            return jsonify({"success": False, "message": f"Unexpected error: {str(e)}"}), 500
    
    @bp.route("/wled_status/add_device/<ip>", methods=["POST"])
    def add_device(ip: str):
        """Add a WLED device to the configuration."""
        try:
            devices_str = rhapi.db.option("wled_devices") or ""
            devices_list = [d.strip() for d in devices_str.split(",") if d.strip()]
            
            # Check if device already exists
            device_entry = f"1:{ip}"
            for existing in devices_list:
                # Check if IP matches (handles both "ip" and "group:ip" formats)
                if ":" in existing:
                    _, existing_ip = existing.split(":", 1)
                    if existing_ip.strip() == ip:
                        return jsonify({
                            "success": False,
                            "message": f"Device {ip} is already configured"
                        }), 400
                elif existing.strip() == ip:
                    return jsonify({
                        "success": False,
                        "message": f"Device {ip} is already configured"
                    }), 400
            
            # Add device with group 1 prefix
            if devices_list:
                new_devices_str = devices_str + f",{device_entry}"
            else:
                new_devices_str = device_entry
            
            rhapi.db.option_set("wled_devices", new_devices_str)
            logger.info(f"Added WLED device {ip} to configuration (group 1)")
            return jsonify({
                "success": True,
                "message": f"Device {ip} added to group 1"
            })
        except Exception as e:
            logger.exception(f"Error adding device {ip}")
            return jsonify({
                "success": False,
                "message": f"Failed to add device: {str(e)}"
            }), 500
    
    @bp.route("/wled_status/update_group", methods=["POST"])
    def update_group():
        """Update the group number for a device. Rebuilds wled_devices string."""
        try:
            data = request.get_json(force=True, silent=True) or {}
            ip = (data.get("ip") or "").strip()
            try:
                new_group = int(data.get("new_group", 1))
            except (TypeError, ValueError):
                new_group = 1
            if new_group < 1:
                new_group = 1
            if not ip:
                return jsonify({"success": False, "message": "IP is required"}), 400
            
            devices_str = rhapi.db.option("wled_devices") or ""
            groups = organize_devices_by_group(devices_str)
            
            # Build list of (group, ip); for the target IP use new_group
            entries = []
            for group_num, ips in groups.items():
                for device_ip in ips:
                    if device_ip == ip:
                        entries.append((new_group, device_ip))
                    else:
                        entries.append((group_num, device_ip))
            
            # Sort by group then ip for stable output
            entries.sort(key=lambda x: (x[0], x[1]))
            new_devices_str = ",".join(f"{g}:{i}" for g, i in entries)
            rhapi.db.option_set("wled_devices", new_devices_str)
            logger.info(f"Updated device {ip} to group {new_group}")
            return jsonify({"success": True, "message": f"Device {ip} set to group {new_group}"})
        except Exception as e:
            logger.exception("Error updating group")
            return jsonify({"success": False, "message": str(e)}), 500
    
    @bp.route("/wled_status/update_description", methods=["POST"])
    def update_description():
        """Update the description for a device. Saves to wled_device_descriptions."""
        try:
            data = request.get_json(force=True, silent=True) or {}
            ip = (data.get("ip") or "").strip()
            description = (data.get("description") or "").strip()
            if not ip:
                return jsonify({"success": False, "message": "IP is required"}), 400
            
            descriptions_str = rhapi.db.option("wled_device_descriptions") or ""
            descriptions = parse_descriptions(descriptions_str)
            descriptions[ip] = description
            new_str = build_descriptions_str(descriptions)
            rhapi.db.option_set("wled_device_descriptions", new_str)
            logger.info(f"Updated description for {ip}")
            return jsonify({"success": True, "message": "Description updated"})
        except Exception as e:
            logger.exception("Error updating description")
            return jsonify({"success": False, "message": str(e)}), 500
    
    @bp.route("/wled_status/scan", methods=["POST"])
    def scan_devices():
        """Scan network for WLED devices. Only returns devices not already configured."""
        try:
            logger.info("=== WLED Device HTTP Scan Requested ===")
            devices = scan_wled_devices(timeout=1.0, max_workers=20)  # HTTP scan with concurrent threads
            
            # Get list of already configured devices
            devices_str = rhapi.db.option("wled_devices") or ""
            configured_ips = get_configured_ips(devices_str)
            
            # Filter out devices that are already configured
            new_devices = [d for d in devices if d.get("ip") not in configured_ips]
            
            logger.info(f"=== Scan Complete: {len(devices)} device(s) found, {len(new_devices)} new device(s) ===")
            return jsonify({
                "success": True, 
                "devices": new_devices, 
                "count": len(new_devices),
                "message": f"Scan complete. Found {len(new_devices)} new device(s) (excluding {len(devices) - len(new_devices)} already configured). Check server logs for details."
            })
        except Exception as e:
            logger.exception("Error scanning for WLED devices")
            return jsonify({
                "success": False, 
                "message": f"Scan failed: {str(e)}. Check server logs for details.",
                "devices": [],
                "count": 0
            }), 500
