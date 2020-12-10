import socket
import scapy.all as scapy
from redis import StrictRedis
import os


# Redis informations
REDIS_IP = os.environ.get("REDIS_IP", None)
REDIS_PORT = os.environ.get("REDIS_PORT", None)
REDIS_PASSWORD = os.environ.get("REDIS_PASSWORD", None)
REDIS_EXPIRATION = os.environ.get("REDIS_EXPIRATION", None)


def arp_scan(subnet):
    """
        Scans the network by sending ARP packets on the given subnet
        and returns a list of dictionnaries with the IPs, MACs and hostnames
    """

    answered = scapy.arping(subnet)[0]

    machines = []
    for i in answered:
        ip, mac = i[1].psrc, i[1].hwsrc
        try:
            host = socket.gethostbyaddr(i[1].psrc)[0]
        except Exception:
            host = "??"
        machines.append({"ip": ip, "mac": mac, "host": host})

    return machines


def strip_suffix(s, suf):
    if s.endswith(suf):
        return s[: -len(suf)]
    return s


def strip_prefix(s, pre):
    if s.startswith(pre):
        return s[len(pre) :]
    return s


def is_host(host):
    return not (len(host) < 3 or "?" in host)


def send_mac(client, maclist):
    payload = ",".join(maclist)
    client.setex("incubator_pamela", REDIS_EXPIRATION, payload)


def send_hostnames(client, hosts_dict={}):
    for key, value in hosts_dict.items():
        client.hset("incubator_pamela_hostnames", key, value)


def format_host(host):
    """
        Strip know prefixes and suffixes
    """

    host = strip_suffix(host, ".lan.urlab.be")
    host = strip_suffix(host, ".lan")
    host = strip_suffix(host, ".local")
    host = strip_suffix(host, "iPodtouch")
    host = strip_suffix(host, "-PC")
    host = strip_suffix(host, "-pc")

    host = strip_prefix(host, "pc-")
    host = strip_prefix(host, "PC-")
    host = strip_prefix(host, "DESKTOP-")
    host = strip_prefix(host, "LAPTOP-")
    host = strip_prefix(host, "iPod-de-")
    host = strip_prefix(host, "iPadde")

    return host


if __name__ == "__main__":
    client = StrictRedis(REDIS_IP, REDIS_PORT, password=REDIS_PASSWORD)
    client.set("incubator_pamela_expiration", REDIS_EXPIRATION)

    macdicts = arp_scan("192.168.1.0/24")

    maclist = list({x["mac"] for x in macdicts})
    send_mac(client, maclist)

    hostnames = {
        x["mac"]: format_host(x["host"]) for x in macdicts if is_host(x["host"])
    }
    send_hostnames(client, hostnames)
