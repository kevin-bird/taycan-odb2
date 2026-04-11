"""
Raw DoIP/UDS protocol implementation over TCP sockets.
No third-party DoIP libraries — those hang on this car.
"""

import socket
import struct
import time
from typing import Optional

DOIP_VERSION = 0x02
DOIP_VERSION_INV = 0xFD

# DoIP payload types
PAYLOAD_VEHICLE_ID_REQUEST = 0x0001
PAYLOAD_VEHICLE_ID_RESPONSE = 0x0004
PAYLOAD_ROUTING_ACTIVATION_REQ = 0x0005
PAYLOAD_ROUTING_ACTIVATION_RESP = 0x0006
PAYLOAD_DIAGNOSTIC_MESSAGE = 0x8001
PAYLOAD_DIAGNOSTIC_POSITIVE_ACK = 0x8002
PAYLOAD_DIAGNOSTIC_NEGATIVE_ACK = 0x8003

# UDS services
UDS_READ_DID = 0x22
UDS_READ_DID_RESPONSE = 0x62
UDS_TESTER_PRESENT = 0x3E
UDS_TESTER_PRESENT_RESPONSE = 0x7E
UDS_READ_DTC = 0x19
UDS_READ_DTC_RESPONSE = 0x59
UDS_SESSION_CONTROL = 0x10
UDS_SESSION_CONTROL_RESPONSE = 0x50
UDS_NEGATIVE_RESPONSE = 0x7F

# NRC codes
NRC_REQUEST_OUT_OF_RANGE = 0x31
NRC_SECURITY_ACCESS_DENIED = 0x33
NRC_RESPONSE_TOO_LONG = 0x14
NRC_SERVICE_NOT_SUPPORTED = 0x11
NRC_SUBFUNCTION_NOT_SUPPORTED = 0x12
NRC_REQUEST_PENDING = 0x78


def build_doip_header(payload_type: int, payload_length: int) -> bytes:
    return struct.pack(">BBHI", DOIP_VERSION, DOIP_VERSION_INV,
                       payload_type, payload_length)


class DoIPConnection:
    """Manages a raw TCP DoIP connection to the gateway."""

    def __init__(self, gateway_ip: str, port: int = 13400,
                 tester_address: int = 0x0E80, timeout: float = 5.0):
        self.gateway_ip = gateway_ip
        self.port = port
        self.tester_address = tester_address
        self.timeout = timeout
        self.sock: Optional[socket.socket] = None
        self.connected = False

    def connect(self) -> bool:
        """Open TCP connection and perform routing activation."""
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.settimeout(self.timeout)
            # Bind to the link-local interface so traffic goes via ENET, not Wi-Fi
            local_ip = _find_link_local_ip()
            if local_ip:
                try:
                    self.sock.bind((local_ip, 0))
                except OSError:
                    pass
            self.sock.connect((self.gateway_ip, self.port))
        except (ConnectionRefusedError, TimeoutError, OSError) as e:
            self.connected = False
            raise ConnectionError(f"TCP connect failed: {e}")

        # Routing activation
        payload = struct.pack(">HB4s", self.tester_address, 0x00, b"\x00" * 4)
        header = build_doip_header(PAYLOAD_ROUTING_ACTIVATION_REQ, len(payload))
        self.sock.sendall(header + payload)

        try:
            resp = self.sock.recv(4096)
            if len(resp) >= 13:
                resp_type = struct.unpack(">H", resp[2:4])[0]
                code = resp[12]
                if resp_type == PAYLOAD_ROUTING_ACTIVATION_RESP and code == 0x10:
                    self.connected = True
                    return True
        except socket.timeout:
            pass

        self.close()
        raise ConnectionError("Routing activation failed")

    def close(self):
        if self.sock:
            try:
                self.sock.close()
            except Exception:
                pass
        self.sock = None
        self.connected = False

    def send_uds(self, target_address: int, uds_payload: bytes,
                 timeout: float = 1.0) -> Optional[bytes]:
        """
        Send a UDS request to an ECU via DoIP and return the UDS response bytes.
        Returns None if no response or target unreachable.
        """
        if not self.sock or not self.connected:
            return None

        diag_payload = struct.pack(">HH", self.tester_address,
                                   target_address) + uds_payload
        header = build_doip_header(PAYLOAD_DIAGNOSTIC_MESSAGE, len(diag_payload))
        self.sock.sendall(header + diag_payload)

        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                remaining = max(0.01, deadline - time.time())
                self.sock.settimeout(remaining)
                data = self.sock.recv(4096)

                if len(data) < 8:
                    continue

                resp_type = struct.unpack(">H", data[2:4])[0]

                if resp_type == PAYLOAD_DIAGNOSTIC_NEGATIVE_ACK:
                    return None

                if resp_type == PAYLOAD_DIAGNOSTIC_POSITIVE_ACK:
                    # Gateway accepted, wait for ECU response
                    continue

                if resp_type == PAYLOAD_DIAGNOSTIC_MESSAGE and len(data) >= 12:
                    uds_response = data[12:]

                    # Handle NRC 0x78 (request pending) — ECU needs more time
                    if (len(uds_response) >= 3 and
                            uds_response[0] == UDS_NEGATIVE_RESPONSE and
                            uds_response[2] == NRC_REQUEST_PENDING):
                        deadline = time.time() + timeout  # reset deadline
                        continue

                    return uds_response

            except socket.timeout:
                break
            except Exception:
                break

        return None

    def tester_present(self, target_address: int,
                       timeout: float = 0.3) -> bool:
        """Send TesterPresent and return True if ECU responds."""
        resp = self.send_uds(target_address,
                             bytes([UDS_TESTER_PRESENT, 0x00]), timeout)
        return resp is not None and len(resp) >= 1 and resp[0] == UDS_TESTER_PRESENT_RESPONSE

    def read_did(self, target_address: int, did: int,
                 timeout: float = 1.0) -> Optional[bytes]:
        """
        Read a DID from an ECU. Returns raw data bytes (after DID echo),
        or None if not supported / no response.
        """
        uds_req = bytes([UDS_READ_DID, (did >> 8) & 0xFF, did & 0xFF])
        resp = self.send_uds(target_address, uds_req, timeout)

        if resp and len(resp) >= 3 and resp[0] == UDS_READ_DID_RESPONSE:
            return resp[3:]  # skip service ID + DID echo
        return None

    def read_did_ascii(self, target_address: int, did: int,
                       timeout: float = 1.0) -> Optional[str]:
        """Read a DID and decode as ASCII string."""
        raw = self.read_did(target_address, did, timeout)
        if raw is None:
            return None
        try:
            text = raw.decode("ascii", errors="replace").strip("\x00").strip()
            if all(32 <= ord(c) < 127 for c in text):
                return text
        except Exception:
            pass
        return raw.hex(" ")

    def read_dtcs(self, target_address: int,
                  status_mask: int = 0xFF,
                  timeout: float = 2.0) -> list[dict]:
        """
        Read DTCs from an ECU (service 0x19, sub 0x02).
        Returns list of {"code": str, "status": int, "status_hex": str}.
        """
        uds_req = bytes([UDS_READ_DTC, 0x02, status_mask])
        resp = self.send_uds(target_address, uds_req, timeout)

        dtcs = []
        if resp and len(resp) >= 3 and resp[0] == UDS_READ_DTC_RESPONSE:
            # resp[1] = sub-function echo, resp[2] = availability mask
            data = resp[3:]
            # Each DTC: 3 bytes ID + 1 byte status
            i = 0
            while i + 3 < len(data):
                dtc_bytes = data[i:i + 3]
                status = data[i + 3] if i + 3 < len(data) else 0
                # Format DTC as standard hex code
                dtc_code = f"{dtc_bytes[0]:02X}{dtc_bytes[1]:02X}{dtc_bytes[2]:02X}"
                if dtc_code != "000000":  # skip empty
                    # A DTC is a real fault only if testFailed (0x01),
                    # confirmedDTC (0x04), or pendingDTC (0x08) is set.
                    # Status 0x10/0x40/0x50 alone = "test not completed"
                    # which is normal, not a fault.
                    is_fault = bool(status & 0x0D)  # bits 0,2,3
                    dtcs.append({
                        "code": dtc_code,
                        "status": status,
                        "status_hex": f"0x{status:02X}",
                        "active": bool(status & 0x01),
                        "confirmed": bool(status & 0x04),
                        "pending": bool(status & 0x08),
                        "is_fault": is_fault,
                    })
                i += 4

        return dtcs

    def change_session(self, target_address: int, session: int = 0x03,
                       timeout: float = 2.0) -> bool:
        """Switch diagnostic session (0x01=default, 0x03=extended)."""
        resp = self.send_uds(target_address,
                             bytes([UDS_SESSION_CONTROL, session]), timeout)
        return (resp is not None and len(resp) >= 1 and
                resp[0] == UDS_SESSION_CONTROL_RESPONSE)


def _find_link_local_ip() -> Optional[str]:
    """Find a 169.254.x.x IP on any active interface (the ENET adapter)."""
    import subprocess
    try:
        result = subprocess.run(["ifconfig"], capture_output=True, text=True, timeout=5)
        for line in result.stdout.split("\n"):
            if "169.254." in line and "inet " in line:
                parts = line.strip().split()
                idx = parts.index("inet") + 1 if "inet" in parts else -1
                if idx > 0 and idx < len(parts):
                    return parts[idx]
    except Exception:
        pass
    return None


def discover_gateway(broadcast_ip: str = "169.254.255.255",
                     port: int = 13400,
                     timeout: float = 3.0) -> Optional[dict]:
    """
    Send DoIP Vehicle Identification Request via UDP broadcast.
    Binds to the link-local interface so the broadcast goes out
    the ENET adapter, not Wi-Fi.
    Returns gateway info dict or None.
    """
    request = build_doip_header(PAYLOAD_VEHICLE_ID_REQUEST, 0)

    # Find the local 169.254.x.x IP to bind to the correct interface
    local_ip = _find_link_local_ip()

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    sock.settimeout(timeout)

    if local_ip:
        try:
            sock.bind((local_ip, 0))
        except OSError:
            pass

    try:
        sock.sendto(request, (broadcast_ip, port))
        data, addr = sock.recvfrom(4096)

        if len(data) < 8:
            return None

        payload = data[8:]
        result = {"ip": addr[0]}

        if len(payload) >= 17:
            result["vin"] = payload[0:17].decode("ascii", errors="replace")
        if len(payload) >= 19:
            result["logical_address"] = struct.unpack(">H", payload[17:19])[0]
        if len(payload) >= 25:
            result["mac"] = payload[19:25].hex(":")

        return result
    except (socket.timeout, OSError):
        return None
    finally:
        sock.close()
