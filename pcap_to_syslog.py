from datetime import datetime
import ipaddress
from pathlib import Path
import socket
import struct


INPUT = Path("./single-node/config/wannacry_malicious_logs/wannacry_malicious_logs.pcap")
OUTPUT = Path("./single-node/config/wannacry_malicious_logs/wannacry_malicious_syslog_full.log")


PCAP_MAGICS = {
    b"\xd4\xc3\xb2\xa1": ("<", 1_000_000),
    b"\xa1\xb2\xc3\xd4": (">", 1_000_000),
    b"\x4d\x3c\xb2\xa1": ("<", 1_000_000_000),
    b"\xa1\xb2\x3c\x4d": (">", 1_000_000_000),
}

TCP_FLAGS = [
    ("FIN", 0x01),
    ("SYN", 0x02),
    ("RST", 0x04),
    ("PSH", 0x08),
    ("ACK", 0x10),
    ("URG", 0x20),
]


def ip_addr(raw):
    return socket.inet_ntoa(raw)


def read_pcap(path):
    with path.open("rb") as f:
        magic = f.read(4)
        if magic == b"\x0a\x0d\x0d\x0a":
            raise ValueError("El archivo parece PCAPNG; este script espera PCAP clasico.")
        if magic not in PCAP_MAGICS:
            raise ValueError("Cabecera PCAP no reconocida.")

        endian, ts_divisor = PCAP_MAGICS[magic]
        header_rest = f.read(20)
        if len(header_rest) != 20:
            raise ValueError("Cabecera PCAP incompleta.")

        _major, _minor, _tz, _sigfigs, _snaplen, linktype = struct.unpack(
            endian + "HHIIII", header_rest
        )

        while True:
            packet_header = f.read(16)
            if not packet_header:
                break
            if len(packet_header) != 16:
                break

            ts_sec, ts_frac, incl_len, _orig_len = struct.unpack(endian + "IIII", packet_header)
            data = f.read(incl_len)
            if len(data) != incl_len:
                break

            yield ts_sec + (ts_frac / ts_divisor), linktype, data


def network_offset(linktype, data):
    if linktype == 1:  # Ethernet
        if len(data) < 14:
            return None
        offset = 14
        ethertype = struct.unpack("!H", data[12:14])[0]
        while ethertype in (0x8100, 0x88A8, 0x9100):
            if len(data) < offset + 4:
                return None
            ethertype = struct.unpack("!H", data[offset + 2 : offset + 4])[0]
            offset += 4
        return offset if ethertype == 0x0800 else None

    if linktype == 101:  # Raw IPv4
        return 0

    if linktype == 113:  # Linux cooked capture
        if len(data) < 16:
            return None
        protocol = struct.unpack("!H", data[14:16])[0]
        return 16 if protocol == 0x0800 else None

    return None


def parse_packet(linktype, data):
    ip_start = network_offset(linktype, data)
    if ip_start is None or len(data) < ip_start + 20:
        return None

    first_byte = data[ip_start]
    version = first_byte >> 4
    ihl = (first_byte & 0x0F) * 4
    if version != 4 or ihl < 20 or len(data) < ip_start + ihl:
        return None

    total_length = struct.unpack("!H", data[ip_start + 2 : ip_start + 4])[0]
    proto = data[ip_start + 9]
    src_ip = ip_addr(data[ip_start + 12 : ip_start + 16])
    dst_ip = ip_addr(data[ip_start + 16 : ip_start + 20])
    transport_start = ip_start + ihl

    result = {
        "src": src_ip,
        "dst": dst_ip,
        "sport": "0",
        "dport": "0",
        "proto": str(proto),
        "service": "unknown",
        "tcp_flags": "-",
        "length": str(total_length),
        "info": f"IPv4 proto={proto}",
    }

    if proto == 6 and len(data) >= transport_start + 20:
        sport, dport = struct.unpack("!HH", data[transport_start : transport_start + 4])
        flags = data[transport_start + 13]
        flag_names = [name for name, bit in TCP_FLAGS if flags & bit]
        service = service_name(sport, dport)
        result.update(
            {
                "sport": str(sport),
                "dport": str(dport),
                "proto": "tcp",
                "service": service,
                "tcp_flags": ",".join(flag_names) if flag_names else "NONE",
                "info": f"TCP {service} flags={','.join(flag_names) if flag_names else 'NONE'}",
            }
        )
    elif proto == 17 and len(data) >= transport_start + 8:
        sport, dport, udp_length = struct.unpack("!HHH", data[transport_start : transport_start + 6])
        service = service_name(sport, dport)
        result.update(
            {
                "sport": str(sport),
                "dport": str(dport),
                "proto": "udp",
                "service": service,
                "tcp_flags": "-",
                "length": str(udp_length),
                "info": f"UDP {service}",
            }
        )
    elif proto == 1 and len(data) >= transport_start + 4:
        icmp_type, icmp_code = struct.unpack("!BB", data[transport_start : transport_start + 2])
        result.update(
            {
                "proto": "icmp",
                "service": "icmp",
                "tcp_flags": "-",
                "info": f"ICMP type={icmp_type} code={icmp_code}",
            }
        )

    return result


def service_name(sport, dport):
    ports = {sport, dport}
    if 445 in ports:
        return "SMB"
    if 139 in ports:
        return "NetBIOS-SSN"
    if 137 in ports:
        return "NetBIOS-NS"
    if 138 in ports:
        return "NetBIOS-DGM"
    return "traffic"


def packet_direction(src_ip, dst_ip):
    src = ipaddress.ip_address(src_ip)
    dst = ipaddress.ip_address(dst_ip)

    if dst.is_multicast:
        return "multicast"
    if dst == ipaddress.ip_address("255.255.255.255") or dst_ip.endswith(".255"):
        return "broadcast"
    if src.is_private and dst.is_private:
        return "internal_to_internal"
    if src.is_private:
        return "internal_to_external"
    if dst.is_private:
        return "external_to_internal"
    return "external_to_external"


def is_broadcast(dst_ip):
    dst = ipaddress.ip_address(dst_ip)
    return dst == ipaddress.ip_address("255.255.255.255") or dst_ip.endswith(".255")


def quote_value(value):
    return str(value).replace("\\", "\\\\").replace('"', '\\"')


def main():
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)

    written = 0
    skipped = 0
    with OUTPUT.open("w", encoding="utf-8", newline="\n") as out:
        for packet_ts, linktype, data in read_pcap(INPUT):
            fields = parse_packet(linktype, data)
            if fields is None:
                skipped += 1
                continue

            timestamp = datetime.fromtimestamp(packet_ts).strftime("%b %d %H:%M:%S")
            direction = packet_direction(fields["src"], fields["dst"])
            broadcast = "true" if is_broadcast(fields["dst"]) else "false"
            flow_id = (
                f"{fields['proto']}:{fields['src']}:{fields['sport']}-"
                f"{fields['dst']}:{fields['dport']}"
            )
            out.write(
                f"{timestamp} wannacry-pcap tshark: "
                f"src={fields['src']} dst={fields['dst']} "
                f"sport={fields['sport']} dport={fields['dport']} "
                f"proto={fields['proto']} service={fields['service']} "
                f"flags=\"{fields['tcp_flags']}\" len={fields['length']} "
                f"direction={direction} broadcast={broadcast} "
                f"flow_id=\"{quote_value(flow_id)}\" "
                f"info=\"{quote_value(fields['info'])}\"\n"
            )
            written += 1

    print(f"[OK] Log generado en {OUTPUT}")
    print(f"[OK] Eventos escritos: {written}")
    print(f"[OK] Paquetes ignorados no IPv4: {skipped}")


if __name__ == "__main__":
    main()
