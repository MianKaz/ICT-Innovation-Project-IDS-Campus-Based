from scapy.arch.windows import get_windows_if_list

print("Available network interfaces:\n")

for iface in get_windows_if_list():
	print(f"Name: {iface['name']}")
	print(f"Description: {iface['description']}")
	print(f"GUID: {iface['guid']}")
	print("-" * 50)