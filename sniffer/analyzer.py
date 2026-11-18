import socket
import struct

PCAP_MAGICS = {
    b"\xd4\xc3\xb2\xa1": ("<", 1_000_000),
    b"\xa1\xb2\xc3\xd4": (">", 1_000_000),
    b"\x4d\x3c\xb2\xa1": ("<", 1_000_000_000),
    b"\xa1\xb2\x3c\x4d": (">", 1_000_000_000),
}

PCAPNG_MAGIC = b"\x0a\x0d\x0d\x0a"

PORT_NAMES = {
    20: "ftp-data", 21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp",
    53: "dns", 67: "dhcp", 68: "dhcp", 69: "tftp", 80: "http",
    110: "pop3", 123: "ntp", 143: "imap", 161: "snmp", 389: "ldap",
    443: "tls", 445: "smb", 587: "smtp", 993: "imaps", 995: "pop3s",
    1900: "ssdp", 3306: "mysql", 3389: "rdp", 5353: "mdns",
    5432: "postgres", 6379: "redis", 8080: "http", 8443: "tls",
}


class ParseError(RuntimeError):
    pass


def iter_packets(path):
    with open(path, "rb") as fh:
        magic = fh.read(4)
        if magic in PCAP_MAGICS:
            endian, ticks = PCAP_MAGICS[magic]
            yield from _iter_pcap(fh, endian, ticks)
        elif magic == PCAPNG_MAGIC:
            yield from _iter_pcapng(fh)
        else:
            raise ParseError("not a pcap or pcapng file")


def _iter_pcap(fh, endian, ticks):
    header = fh.read(20)
    if len(header) < 20:
        raise ParseError("truncated pcap header")
    link_type = struct.unpack(endian + "I", header[16:20])[0]
    record = struct.Struct(endian + "IIII")

    while True:
        raw = fh.read(16)
        if len(raw) < 16:
            return
        ts_sec, ts_frac, incl_len, orig_len = record.unpack(raw)
        data = fh.read(incl_len)
        if len(data) < incl_len:
            return
        yield ts_sec + ts_frac / ticks, data, orig_len, link_type


def _iter_pcapng(fh):
    head = fh.read(8)
    if len(head) < 8:
        raise ParseError("truncated pcapng header")

    if head[4:8] == b"\x4d\x3c\x2b\x1a":
        endian = "<"
    elif head[4:8] == b"\x1a\x2b\x3c\x4d":
        endian = ">"
    else:
        raise ParseError("unknown pcapng byte order")

    total = struct.unpack(endian + "I", head[0:4])[0]
    if total < 12:
        raise ParseError("bad pcapng section header")
    fh.seek(total - 12, 1)

    link_types = []

    while True:
        block_head = fh.read(8)
        if len(block_head) < 8:
            return
        block_type, total = struct.unpack(endian + "II", block_head)
        if total < 12:
            raise ParseError("bad pcapng block length")

        body = fh.read(total - 12)
        if len(body) < total - 12:
            return
        fh.read(4)

        if block_type == 0x00000001 and len(body) >= 2:
            link_types.append(struct.unpack(endian + "H", body[0:2])[0])

        elif block_type == 0x00000006 and len(body) >= 20:
            iface, ts_high, ts_low, cap_len, orig_len = struct.unpack(
                endian + "IIIII", body[0:20]
            )
            link = link_types[iface] if iface < len(link_types) else 1
            ts = ((ts_high << 32) | ts_low) / 1_000_000
            yield ts, body[20:20 + cap_len], orig_len, link

        elif block_type == 0x00000003 and len(body) >= 4:
            orig_len = struct.unpack(endian + "I", body[0:4])[0]
            link = link_types[0] if link_types else 1
            yield 0.0, body[4:], orig_len, link

        elif block_type == 0x0A0D0D0A:
            link_types = []


def parse_packet(data, link_type):
    if link_type == 1:
        if len(data) < 14:
            return None
        ethertype = struct.unpack(">H", data[12:14])[0]
        offset = 14
        while ethertype in (0x8100, 0x88A8) and len(data) >= offset + 4:
            ethertype = struct.unpack(">H", data[offset + 2:offset + 4])[0]
            offset += 4

    elif link_type == 113:
        if len(data) < 16:
            return None
        ethertype = struct.unpack(">H", data[14:16])[0]
        offset = 16

    elif link_type == 276:
        if len(data) < 20:
            return None
        ethertype = struct.unpack(">H", data[0:2])[0]
        offset = 20

    elif link_type in (101, 228):
        ethertype, offset = 0x0800, 0

    elif link_type == 229:
        ethertype, offset = 0x86DD, 0

    else:
        return None

    if ethertype == 0x0800:
        return _parse_ipv4(data, offset)
    if ethertype == 0x86DD:
        return _parse_ipv6(data, offset)
    if ethertype == 0x0806:
        return {"proto": "arp"}
    return {"proto": "other"}


def _parse_ipv4(data, offset):
    if len(data) < offset + 20:
        return None
    header_length = (data[offset] & 0x0F) * 4
    if header_length < 20:
        return None
    protocol = data[offset + 9]
    src = socket.inet_ntop(socket.AF_INET, data[offset + 12:offset + 16])
    dst = socket.inet_ntop(socket.AF_INET, data[offset + 16:offset + 20])
    return _parse_transport(data, offset + header_length, protocol, src, dst)


def _parse_ipv6(data, offset):
    if len(data) < offset + 40:
        return None
    protocol = data[offset + 6]
    src = socket.inet_ntop(socket.AF_INET6, data[offset + 8:offset + 24])
    dst = socket.inet_ntop(socket.AF_INET6, data[offset + 24:offset + 40])
    return _parse_transport(data, offset + 40, protocol, src, dst)


def _parse_transport(data, offset, protocol, src, dst):
    base = {"src": src, "dst": dst, "sport": None, "dport": None, "payload": b""}

    if protocol == 6 and len(data) >= offset + 4:
        sport, dport = struct.unpack(">HH", data[offset:offset + 4])
        payload = b""
        if len(data) >= offset + 20:
            header_length = max(20, (data[offset + 12] >> 4) * 4)
            payload = data[offset + header_length:]
        return {**base, "transport": "tcp", "sport": sport, "dport": dport,
                "payload": payload}

    if protocol == 17 and len(data) >= offset + 8:
        sport, dport = struct.unpack(">HH", data[offset:offset + 4])
        return {**base, "transport": "udp", "sport": sport, "dport": dport,
                "payload": data[offset + 8:]}

    if protocol == 1:
        return {**base, "transport": "icmp"}
    if protocol == 58:
        return {**base, "transport": "icmpv6"}

    return {**base, "transport": "ip"}

def _read_dns_name(payload, offset, depth=0):
    labels = []

    while True:
        if depth > 5 or offset >= len(payload):
            return None, offset

        length = payload[offset]

        if length == 0:
            return labels, offset + 1

        if length & 0xC0 == 0xC0:
            if offset + 2 > len(payload):
                return None, offset
            pointer = struct.unpack(">H", payload[offset:offset + 2])[0] & 0x3FFF
            tail, _ = _read_dns_name(payload, pointer, depth + 1)
            if tail is None:
                return None, offset + 2
            return labels + tail, offset + 2

        offset += 1
        if offset + length > len(payload):
            return None, offset
        labels.append(payload[offset:offset + length])
        offset += length


def dns_query_names(payload):
    if len(payload) < 12:
        return []

    flags, qdcount = struct.unpack(">HH", payload[2:6])
    if flags & 0x8000 or not 0 < qdcount <= 64:
        return []

    names = []
    offset = 12

    for _ in range(qdcount):
        labels, offset = _read_dns_name(payload, offset)
        if labels is None:
            break
        offset += 4
        if offset > len(payload):
            break
        if not labels:
            continue
        try:
            names.append(b".".join(labels).decode("utf-8").lower())
        except UnicodeDecodeError:
            continue

    return names

def tls_server_name(payload):
    if len(payload) < 44 or payload[0] != 0x16 or payload[5] != 0x01:
        return None

    pos = 43
    if pos >= len(payload):
        return None
    pos += 1 + payload[pos]

    if pos + 2 > len(payload):
        return None
    pos += 2 + struct.unpack(">H", payload[pos:pos + 2])[0]

    if pos >= len(payload):
        return None
    pos += 1 + payload[pos]

    if pos + 2 > len(payload):
        return None
    end = min(pos + 2 + struct.unpack(">H", payload[pos:pos + 2])[0], len(payload))
    pos += 2

    while pos + 4 <= end:
        ext_type, ext_len = struct.unpack(">HH", payload[pos:pos + 4])
        pos += 4
        if ext_type == 0x0000:
            if pos + 5 > len(payload):
                return None
            name_len = struct.unpack(">H", payload[pos + 3:pos + 5])[0]
            start = pos + 5
            if start + name_len > len(payload):
                return None
            name = payload[start:start + name_len].decode("ascii", "replace")
            return name.strip().rstrip(".").lower() or None
        pos += ext_len

    return None


def protocol_name(transport, sport, dport):
    for port in (sport, dport):
        if port in PORT_NAMES:
            return PORT_NAMES[port]
    return transport


def analyze(path):
    flows = {}
    protocols = {}
    dns = {}
    packets = 0
    total_bytes = 0

    for _ts, data, orig_len, link_type in iter_packets(path):
        packets += 1
        total_bytes += orig_len

        info = parse_packet(data, link_type)

        if info is None:
            protocols["unknown"] = protocols.get("unknown", 0) + 1
            continue

        if "src" not in info:
            label = info["proto"]
            protocols[label] = protocols.get(label, 0) + 1
            continue

        transport = info["transport"]
        label = protocol_name(transport, info["sport"], info["dport"])
        protocols[label] = protocols.get(label, 0) + 1

        if label in ("dns", "mdns") and info["payload"]:
            for name in dns_query_names(info["payload"]):
                dns[name] = dns.get(name, 0) + 1

        a = (info["src"], info["sport"] if info["sport"] is not None else -1)
        b = (info["dst"], info["dport"] if info["dport"] is not None else -1)
        key = tuple(sorted([a, b])) + (transport,)

        flow = flows.setdefault(key, {"packets": 0, "bytes": 0,
                                      "proto": transport, "host": None})
        flow["packets"] += 1
        flow["bytes"] += orig_len
        if label != transport:
            flow["proto"] = label

        if transport == "tcp" and flow["host"] is None and info["payload"]:
            host = tls_server_name(info["payload"])
            if host:
                flow["host"] = host

    if packets == 0:
        raise ParseError("no packets in file")

    conversations = []
    sites = {}

    for (a, b, transport), flow in flows.items():
        conversations.append({
            "a": f"{a[0]}:{a[1]}" if a[1] >= 0 else a[0],
            "b": f"{b[0]}:{b[1]}" if b[1] >= 0 else b[0],
            "transport": transport,
            **flow,
        })

        if flow["host"]:
            site = sites.setdefault(flow["host"],
                                    {"packets": 0, "bytes": 0, "connections": 0})
            site["packets"] += flow["packets"]
            site["bytes"] += flow["bytes"]
            site["connections"] += 1

    conversations.sort(key=lambda c: c["bytes"], reverse=True)

    site_rows = [{"host": host, **counts} for host, counts in sites.items()]
    site_rows.sort(key=lambda s: s["bytes"], reverse=True)

    return {
        "packets": packets,
        "total_bytes": total_bytes,
        "conversations": conversations,
        "sites": site_rows,
        "protocols": sorted(protocols.items(), key=lambda kv: -kv[1]),
        "dns": sorted(dns.items(), key=lambda kv: -kv[1]),
    }