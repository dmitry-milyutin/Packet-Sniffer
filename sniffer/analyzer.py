import subprocess

# One column per packet, in this order.
FIELDS = [
    "frame.len",
    "frame.protocols",
    "ip.src",
    "ip.dst",
    "tcp.srcport",
    "tcp.dstport",
    "udp.srcport",
    "udp.dstport",
]

# Layers that say how a packet travelled, not what it carried.
TRANSPORT = {"eth", "ethertype", "ip", "ipv6", "tcp", "udp", "arp", "data"}


def run_tshark(path, fields, display_filter=None):
    """Run tshark and return its output as a list of lines."""
    cmd = ["tshark", "-r", path, "-T", "fields", "-E", "separator=\t"]
    if display_filter:
        cmd += ["-Y", display_filter]
    for field in fields:
        cmd += ["-e", field]

    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip().split("\n")[-1])
    return result.stdout.splitlines()


def analyze(path):
    flows = {}
    protocols = {}
    packets = 0
    total_bytes = 0

    for line in run_tshark(path, FIELDS):
        cols = line.split("\t")
        cols += [""] * (len(FIELDS) - len(cols))   # tshark drops empty columns
        length, protos, src, dst, tcp_s, tcp_d, udp_s, udp_d = cols

        packets += 1
        size = int(length) if length else 0
        total_bytes += size

        proto = protos.split(":")[-1] if protos else "?"
        protocols[proto] = protocols.get(proto, 0) + 1

        if not src or not dst:
            continue

        if tcp_s:
            transport, sport, dport = "tcp", tcp_s, tcp_d
        elif udp_s:
            transport, sport, dport = "udp", udp_s, udp_d
        else:
            transport, sport, dport = proto, "", ""

        # sorted() makes A->B and B->A the same key, so both directions of a
        # conversation land in one entry
        key = tuple(sorted([(src, sport), (dst, dport)])) + (transport,)

        flow = flows.setdefault(key, {"packets": 0, "bytes": 0, "proto": transport})
        flow["packets"] += 1
        flow["bytes"] += size
        if proto not in TRANSPORT:
            flow["proto"] = proto      # prefer tls/http/dns over plain "tcp"

    dns = {}
    for name in run_tshark(path, ["dns.qry.name"], "dns.flags.response == 0"):
        name = name.strip().rstrip(".").lower()
        if name:
            dns[name] = dns.get(name, 0) + 1

    conversations = []
    for (a, b, transport), flow in flows.items():
        conversations.append({
            "a": f"{a[0]}:{a[1]}" if a[1] else a[0],
            "b": f"{b[0]}:{b[1]}" if b[1] else b[0],
            "transport": transport,
            **flow,
        })
    conversations.sort(key=lambda c: c["bytes"], reverse=True)

    return {
        "packets": packets,
        "total_bytes": total_bytes,
        "conversations": conversations,
        "protocols": sorted(protocols.items(), key=lambda kv: -kv[1]),
        "dns": sorted(dns.items(), key=lambda kv: -kv[1]),
    }