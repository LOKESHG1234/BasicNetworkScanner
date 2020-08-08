# Goal->Discover Clients on network
#  Steps:-
#  1. Create arp request directed to broadcast MAC asking for IP 
#  2. Send Packet and receive response
#  3. Parse the response
#  4. Print Result.
# There is onr moremodule named argparse for python3 fuction is same as optparse just classes and function names are different and when instead og parse_args the argparse module function is called it only return option and not argumnet
import scapy.all as scapy
import optparse
import socket
def get_arguments():
	parser = optparse.OptionParser()
	parser.add_option("-t", "--target", dest="target", help="Target to be set")
	(options, arguments)=parser.parse_args()
	if not options.target:
		print("[-] Please specify the target IP,Check help for more details")
	return options
def scan(ip):
	arp_request = scapy.ARP(pdst=ip)
	broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
	arp_request_broadcast = broadcast/arp_request
	answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0] # Send and receive Packet so we need to capture the value in a variable the response returns two lists what Verbose does is it doesnot print the Begin emmision to remaining packets line and thats all it does by setting verbose to false
	clients_list=[]
	for element in answered_list:
		client_dict={"IP":element[1].psrc, "MAC":element[1].hwsrc}
		clients_list.append(client_dict)
	return clients_list

def print_result(results_list):
	print("IP\t\t\tMAC Address\n-----------------------------------------")
	for client in results_list:
		print(client["IP"] + "\t\t" + client["MAC"])
	for client in results_list:
		print(f'Port Scanning for {client["IP"]}')
		port_scan(client["IP"])

def port_scan(target):
	try:
		for port in range(1,65535):
			s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
			socket.setdefaulttimeout(1)
			result = s.connect_ex((target, port))
			if result == 0:
				print(f"Port {port} is open")
			else:
				pass
	except KeyboardInterrupt:
		exit()	
	

options = get_arguments()
scan_result = scan(options.target)
print_result(scan_result)

