"""Example of Netmiko Configuration"""

from netmiko import ConnectHandler
import time
from pathlib import Path

DEVICES_IP = ["172.31.9.5","172.31.9.11","172.31.9.4"]
USERNAME = "WINDOWS_USER"

BASE_DEVICE_PARAMS = {
    "device_type": "cisco_ios",
    "username": USERNAME,
    "use_keys": True,
    "key_file": r"C:\Users\Lenovo\Desktop\key\id_rsa",
    "disabled_algorithms": {
        "pubkeys": ["rsa-sha2-256", "rsa-sha2-512"],
        "kex": [
            "diffie-hellman-group1-sha1",
            "diffie-hellman-group14-sha256",
            "diffie-hellman-group16-sha512",
            "diffie-hellman-group18-sha512",
            "diffie-hellman-group-exchange-sha256",
            "ecdh-sha2-nistp256",
            "ecdh-sha2-nistp384",
            "ecdh-sha2-nistp521",
            "curve25519-sha256",
            "curve25519-sha256@libssh.org",
        ],
        "hostkeys": [
            "ssh-ed25519",
            "ecdsa-sha2-nistp256",
            "ecdsa-sha2-nistp384",
            "ecdsa-sha2-nistp521",
        ],
    },
    "allow_agent": False
}
COMMAND_SET_VLAN = [
    "vlan 101",
    "name ControlData",
    "exit",
    "int range g0/1, g1/1",
    "switchport mode access",
    "switchport access vlan 101"
]

COMMAND_SET_OSPF_R1 = [
    "int g0/2",
    "no shut",
    "ip add 172.31.10.1 255.255.255.0",
    "int lo0",
    "ip add 1.1.1.1 255.255.255.255",
    "router ospf 10 vrf ControlData",
    "network 172.31.20.0 0.0.0.255 area 0",
    "network 172.31.10.0 0.0.0.255 area 0",
    "network 1.1.1.1 0.0.0.0 area 0"
]

COMMAND_SET_OSPF_R2 = [
    "int g0/3",
    "vrf forwarding ControlData",
    "no shut",
    "ip add dhcp",
    "int g0/1",
    "no shut",
    "ip add 172.31.18.18 255.255.255.252",
    "int lo0",
    "ip add 2.2.2.2 255.255.255.255",
    "exit",
    "ip route vrf ControlData 0.0.0.0 0.0.0.0 192.168.85.1",
    "router ospf 10 vrf ControlData",
    "network 172.31.20.0 0.0.0.255 area 0",
    "network 172.31.30.0 0.0.0.255 area 0",
    "network 2.2.2.2 0.0.0.0 area 0",
    "default-information originate always"
]

COMMAND_SET_PATR2 = [
    "int g0/3",
    "ip nat outside",
    "int range g0/1-2",
    "ip nat inside",
    "exit",
    "access-list 1 permit 172.31.0.0 0.0.255.255",
    "ip nat inside source list 1 interface g0/3 vrf ControlData overload"
]

for ip in DEVICES_IP:
    print(f"Connecting to {ip}...")

    device_params = BASE_DEVICE_PARAMS.copy()
    device_params["ip"] = ip

    if ip == "172.31.9.11":
        command_set = COMMAND_SET_VLAN
    elif ip == "172.31.9.5":
        command_set = COMMAND_SET_OSPF_R1
    elif ip == "172.31.9.4":
        command_set = COMMAND_SET_OSPF_R2

    with ConnectHandler(**device_params) as ssh:
        ssh.enable()
        print(f"Connected to {ip}")
        result = ssh.send_config_set(command_set)
        print(f"Configuration result for {ip}:\n{result}")
        time.sleep(2)
        if device_params["ip"] == "":
            command_set = COMMAND_SET_PATR2
            result = ssh.send_config_set(command_set)
            print(f"Configuration result for PAT Router {ip}:\n{result}")
        time.sleep(1)
        print(f"Finished configuration for {ip}")