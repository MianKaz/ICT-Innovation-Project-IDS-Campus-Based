from scapy.all import get_if_list

print("Available network interfaces:\n")

for interface in get_if_list():
    print(interface)