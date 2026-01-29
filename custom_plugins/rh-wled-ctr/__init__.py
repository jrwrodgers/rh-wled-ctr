'''WLED Controller Plugin for RotorHazard'''
import logging
logger = logging.getLogger(__name__)
import RHData
from eventmanager import Evt
from EventActions import ActionEffect
from RHUI import UIField, UIFieldType
import requests
from requests.adapters import HTTPAdapter
from . import wled_status_page


def _post_no_pool(url: str, json_payload: dict, timeout: float = 2) -> bool:
    """POST without connection pooling to avoid gevent/urllib3 cleanup issues."""
    session = requests.Session()
    adapter = HTTPAdapter(pool_connections=0, pool_maxsize=0)
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    response = None
    try:
        response = session.post(url, json=json_payload, timeout=timeout, stream=False)
        return response.status_code == 200
    except requests.RequestException:
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


def send_wled_json(devices: list, payload: dict, timeout: int = 2) -> None:
    """Send a JSON payload to each WLED device. Logs errors but does not raise."""
    for device in devices:
        url = f"http://{device}/json/state"
        try:
            if _post_no_pool(url, payload, timeout=float(timeout)):
                logger.info(f"WLED packet sent to {device}")
            else:
                logger.error(f"WLED request failed for {device}")
        except Exception as e:
            logger.error(f"WLED request failed for {device}: {e}")


def parse_rgb(s: str) -> tuple[int, int, int]:
   # logger.info(f"Parsing RGB: {s}")
    s=str(s).split(',')
   # logger.info(f"Parsing RGB: {s}")

    if len(s) != 3:
        raise ValueError("RGB must have exactly 3 values")

    rgb = []
    for p in s:
        if not p.strip().isdigit():
            raise ValueError(f"Invalid integer value: {p}")

        value = int(p)
        if not 0 <= value <= 255:
            raise ValueError(f"RGB value out of range: {value}")

        rgb.append(value)

    return tuple(rgb)

def _int_or_default(val, default: int) -> int:
    """Return int(val), or default if val is missing, empty, or invalid."""
    if val is None or (isinstance(val, str) and not str(val).strip()):
        return default
    try:
        return int(val)
    except (ValueError, TypeError):
        return default


def _action_colour_to_rgb(val) -> tuple[int, int, int]:
    """Convert action colour to (r,g,b). Accepts '255,0,0' or [255,0,0] / (255,0,0)."""
    if val is None:
        return (255, 255, 255)
    if isinstance(val, (list, tuple)) and len(val) >= 3:
        try:
            r = max(0, min(255, int(val[0])))
            g = max(0, min(255, int(val[1])))
            b = max(0, min(255, int(val[2])))
            return (r, g, b)
        except (ValueError, TypeError):
            pass
    if isinstance(val, str) and val.strip():
        try:
            return parse_rgb(val)
        except ValueError:
            pass
    return (255, 255, 255)


def get_ips_for_group(s: str, group: int) -> list[str]:
    """Return IPs for the given group. Entries without ':' are treated as group 1."""
    try:
        if s is None:
            logger.debug("get_ips_for_group: devices string is None, returning empty list")
            return []
        if not isinstance(s, str):
            logger.warning(f"get_ips_for_group: expected str, got {type(s).__name__}")
            s = str(s)
        if not isinstance(group, int) or group < 1:
            logger.warning(f"get_ips_for_group: invalid group {group!r}, using 1")
            group = 1

        prefix = f"{group}:"
        ips = []

        for entry in s.split(","):
            entry = entry.strip()
            if not entry:
                continue
            if ":" in entry:
                if entry.startswith(prefix):
                    _, ip = entry.split(":", 1)
                    ips.append(ip.strip())
            elif group == 1:
                ips.append(entry)

        return ips
    except Exception as e:
        logger.error(f"get_ips_for_group failed: {e}", exc_info=True)
        return []


def get_all_ips(s: str) -> list[str]:
    """Return all device IPs from the devices string (any group)."""
    if not s or not isinstance(s, str):
        return []
    ips = []
    for entry in str(s).split(","):
        entry = entry.strip()
        if not entry:
            continue
        if ":" in entry:
            _, ip = entry.split(":", 1)
            ips.append(ip.strip())
        else:
            ips.append(entry)
    return ips


def build_wled_json_packet(color, mode, speed, intensity, power):
    # WLED JSON API expects boolean true/false, not strings
    packet = {
        "on": bool(power == 1),
        "bri": 255,
        "seg": [{
            "id": 0,
            "col": [[color[0], color[1], color[2]]],
            "fx": mode,
            "sx": speed,
            "ix": intensity
        }]
    }
    return packet





class WLEDController():
    def __init__(self, rhapi):
        self._rhapi = rhapi

    def WLEDMessageSend(self, action, args):
        try:
            # Use defaults when values are missing or empty
            rgb = _action_colour_to_rgb(action.get("wled_colour"))

            speed = _int_or_default(action.get("wled_speed"), 128)
            intensity = _int_or_default(action.get("wled_intensity"), 128)
            power = _int_or_default(action.get("wled_power"), 1)
            mode = _int_or_default(action.get("wled_mode"), 0)
            group = _int_or_default(action.get("wled_group"), 1)

            wled_devices_str = self._rhapi.db.option("wled_devices") or ""
            wled_devices = get_ips_for_group(str(wled_devices_str), group=group)
            #logger.info(f"WLED devices: {wled_devices}")
                         
            payload = build_wled_json_packet(
                power=power, color=rgb, mode=mode, speed=speed, intensity=intensity
            )

            if wled_devices:
                send_wled_json(wled_devices, payload)
                logger.info(f"WLED packet sent to {len(wled_devices)} device(s) (mode={mode}, rgb={rgb[0]},{rgb[1]},{rgb[2]})")
            else:
                logger.warning(f"No WLED devices for group {group}")
        except Exception as e:
            logger.error(f"WLED action error: {e}")


    def register_handlers(self, args):
            if 'register_fn' in args:
                for effect in [
                    ActionEffect(
                        'WLED Controller',
                        self.WLEDMessageSend,
                        [
                            UIField('wled_group', "Group", UIFieldType.TEXT),
                            UIField('wled_colour', "Colour (R,G,B)", UIFieldType.TEXT),
                            UIField('wled_mode', "Mode", UIFieldType.TEXT),
                            UIField('wled_speed', "Speed", UIFieldType.TEXT),
                            UIField('wled_intensity', "Intensity", UIFieldType.TEXT),
                            UIField('wled_power', "Power", UIFieldType.TEXT)
                        ]
                    )
                ]:
                    args['register_fn'](effect)

            


def initialize(rhapi):
    wled_controller = WLEDController(rhapi)
    rhapi.events.on(Evt.ACTIONS_INITIALIZE, wled_controller.register_handlers)
    rhapi.ui.register_panel('wled_options', 'WLED Setup', 'settings', order=0)
    rhapi.fields.register_option(UIField('wled_devices', 'WLED Devices', UIFieldType.TEXT), 'wled_options')
    rhapi.fields.register_option(UIField('wled_test_group', 'Test Group', UIFieldType.TEXT), 'wled_options')
    
    # Add link to WLED status webpage
    rhapi.ui.register_markdown('wled_options', 'wled_status_link', 
                                '<p><a href="/wled_status" target="_blank">View WLED Device Status Page</a></p>')
    
    # Set up WLED status webpage routes
    wled_status_page.setup_wled_routes(rhapi)
    rhapi.ui.blueprint_add(wled_status_page.bp)

    def on_test_led(*_args):
        try:
            group_val = rhapi.db.option("wled_test_group") or "1"
            group = _int_or_default(group_val, 1)
            devices_str = rhapi.db.option("wled_devices") or ""
            devices = get_ips_for_group(str(devices_str), group=group)
            if not devices:
                logger.warning(f"No WLED devices for group {group}")
                rhapi.ui.message_notify(f"No WLED devices for group {group}")
                return
            payload = build_wled_json_packet(
                color=(0, 100, 0), mode=1, speed=128, intensity=128, power=1
            )
            send_wled_json(devices, payload)
            rhapi.ui.message_notify(f"Test LED sent (green, blink) to group {group}")
        except Exception as e:
            logger.exception("Test LED failed")
            rhapi.ui.message_notify(f"Test LED failed: {e}")

    def on_turn_off(*_args):
        try:
            devices_str = rhapi.db.option("wled_devices") or ""
            devices = get_all_ips(str(devices_str))
            if not devices:
                logger.warning("No WLED devices configured")
                rhapi.ui.message_notify("No WLED devices configured")
                return
            send_wled_json(devices, {"on": False})
            rhapi.ui.message_notify("Turned off all WLED devices")
        except Exception as e:
            logger.exception("Turn off LEDs failed")
            rhapi.ui.message_notify(f"Turn off failed: {e}")

    rhapi.ui.register_quickbutton('wled_options', 'wled_test_led', 'Test WLED Devices', on_test_led)
    rhapi.ui.register_quickbutton('wled_options', 'wled_turn_off', 'Turn Off WLED Devices', on_turn_off)

# WLED_MODES = {
#     0: "Solid",
#     1: "Blink",
#     2: "Breathe",
#     3: "Wipe",
#     4: "Wipe Random",
#     5: "Random Colors",
#     6: "Sweep",
#     7: "Dynamic",
#     8: "Colorloop",
#     9: "Rainbow",
#     10: "Scan",
#     11: "Dual Scan",
#     12: "Fade",
#     13: "Theater Chase",
#     14: "Theater Chase Rainbow",
#     15: "Running Lights",
#     16: "Saw",
#     17: "Twinkle",
#     18: "Dissolve",
#     19: "Dissolve Random",
#     20: "Sparkle",
#     21: "Flash Sparkle",
#     22: "Hyper Sparkle",
#     23: "Strobe",
#     24: "Strobe Rainbow",
#     25: "Mega Strobe",
#     26: "Blink Rainbow",
#     27: "Android",
#     28: "Chase",
#     29: "Chase Random",
#     30: "Chase Rainbow",
#     31: "Chase Flash",
#     32: "Chase Flash Random",
#     33: "Chase Rainbow White",
#     34: "Colorful",
#     35: "Traffic Light",
#     36: "Sweep Random",
#     37: "Running Color",
#     38: "Running Red Blue",
#     39: "Running Random",
#     40: "Larson Scanner",
#     41: "Comet",
#     42: "Fireworks",
#     43: "Rain",
#     44: "Tetrix",
#     45: "Fire Flicker",
#     46: "Gradient",
#     47: "Loading",
#     48: "Rolling Ball",
#     49: "Fairy",
#     50: "Two Dots",
#     51: "Fairytwinkle",
#     52: "Running Dual",
#     53: "Halloween",
#     54: "Chase 3",
#     55: "Tri Wipe",
#     56: "Tri Fade",
#     57: "Lightning",
#     58: "ICU",
#     59: "Multi Comet",
#     60: "Scanner Dual",
#     61: "Stream",
#     62: "Oscillate",
#     63: "Pride 2015",
#     64: "Juggle",
#     65: "Palette",
#     66: "Fire 2012",
#     67: "Colorwaves",
#     68: "BPM",
#     69: "Fill Noise",
#     70: "Noise 1",
#     71: "Noise 2",
#     72: "Noise 3",
#     73: "Noise 4",
#     74: "Colortwinkles",
#     75: "Lake",
#     76: "Meteor",
#     77: "Smooth Meteor",
#     78: "Railgun",
#     79: "Ripple",
#     80: "Twinklefox",
#     81: "Twinklecat",
#     82: "Halloween Eyes",
#     83: "Solid Glitter",
#     84: "Sunset",
#     85: "Splash",
#     86: "Spellbound",
#     87: "Solid Pattern",
#     88: "Candle",
#     89: "Fireworks Starburst",
# }
