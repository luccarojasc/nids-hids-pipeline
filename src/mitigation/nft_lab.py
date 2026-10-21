"""Renderização restrita ao namespace descartável da demonstração."""
import re
import subprocess

TABLE = "tcc6_demo"
SET = "ssh_block"
CLIENT = "192.0.2.2"
SERVER = "192.0.2.1"


def namespace(value):
    if not re.fullmatch(r"tcc6_srv_[0-9a-f]{8}", value):
        raise ValueError("Namespace de laboratório inválido")
    return value


def setup_batch():
    return (f"add table inet {TABLE}\n"
            f"add set inet {TABLE} {SET} {{ type ipv4_addr; flags timeout; }}\n"
            f"add chain inet {TABLE} input {{ type filter hook input priority 0; policy accept; }}\n"
            f"add rule inet {TABLE} input ip saddr @{SET} ip daddr {SERVER} tcp dport 22 counter drop\n")


def action_batch(action, ttl_s):
    if action not in ("apply", "renew") or type(ttl_s) is not int or ttl_s not in (6, 12, 900, 1800):
        raise ValueError("Ação/TTL fora dos perfis de demonstração")
    delete = f"delete element inet {TABLE} {SET} {{ {CLIENT} }}\n" if action == "renew" else ""
    return delete + f"add element inet {TABLE} {SET} {{ {CLIENT} timeout {ttl_s}s }}\n"


def invoke(ns, batch):
    argv = ["ip", "netns", "exec", namespace(ns), "nft", "-f", "-"]
    return subprocess.run(argv, input=batch, text=True, capture_output=True, check=True, timeout=10)