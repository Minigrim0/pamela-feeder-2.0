import socket
import scapy.all as scapy
from redis import StrictRedis


def arp_scan(subnet):
    arp_r = scapy.ARP(pdst=subnet)
    br = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    request = br / arp_r
    answered, _ = scapy.srp(request, timeout=1)

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
    if "?" in host:
        return False
    if len(host) < 3:
        return False

    return True


def send_mac(client, maclist):
    payload = ",".join(maclist)
    client.setex("incubator_pamela", 300, payload)


def send_hostnames(client, hosts_dict):
    if hosts_dict:
        client.hmset("incubator_pamela_hostnames", hosts_dict)


def format_host(host):
    host = strip_suffix(host, ".lan.urlab.be")
    host = strip_suffix(host, ".lan")
    host = strip_suffix(host, ".local")

    host = strip_suffix(host, "iPodtouch")
    host = strip_suffix(host, "-PC")
    host = strip_suffix(host, "-pc")

    host = strip_prefix(host, "pc-")
    host = strip_prefix(host, "PC-")

    host = strip_prefix(host, "LAPTOP-")
    host = strip_prefix(host, "iPod-de-")

    # if host.startswith("android"):
    #     match = re.match(ANDROID_REGEX, host)
    #     if match:
    #         host = "unknown-android"
    #     else:
    #         host = strip_prefix(host, "android-")
    return host


# @periodic(PERIOD)
def main(client):
    macdicts = arp_scan("192.168.1.0/24")

    maclist = list({x["mac"] for x in macdicts})
    print(maclist)
    send_mac(client, maclist)

    hostnames = {
        x["mac"]: format_host(x["host"]) for x in macdicts if is_host(x["host"])
    }
    print(hostnames)
    send_hostnames(client, hostnames)


client = StrictRedis("172.28.1.4", 6379, password="modepass")
client.set("incubator_pamela_expiration", 300)

main(client)
