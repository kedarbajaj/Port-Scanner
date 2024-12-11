import sys
import requests
import socket
import json

if len(sys.argv) < 2:
    print("Usage: " + sys.argv[0] + " <url>")
    sys.exit(1)

req = requests.get("https://"+sys.argv[1])
print("\n"+str(req.headers))

gethostby_ = socket.gethostbyname(sys.argv[1])
print("\nThe IP address of "+sys.argv[1]+" is: "+gethostby_ + "\n")

#ipinfo.io

req_two = requests.get("https://ipinfo.io/"+gethostby_+"/json")
resp_ = json.loads(req_two.text)

print("Location: "+resp_["loc"])
print("Region: "+resp_["region"])
print("City: "+resp_["city"])
print("Country: "+resp_["country"])
import argparse
import nmap

def argument_parser():
    """Allow target to specify target host and port"""
    parser = argparse.ArgumentParser(description = "TCP port scanner. accept a hostname/IP address and list of ports to"
                                     "scan. Attenpts to identify the service running on a port.")
    parser.add_argument("-o", "--host", nargs = "?", help = "Host IP address")
    parser.add_argument("-p", "--ports", nargs="?", help = "comma-separation port list, such as '25,80,8080'")

    var_args = vars(parser.parse_args()) # Convert argument name space to dictionary
    return var_args

def nmap_scan(host_id, port_num):
    """Use nmap utility to check host ports for status."""
    nm_scan = nmap.PortScanner()
    nm_scan.scan(host_id, port_num)
    state = nm_scan[host_id]['tcp'][int(port_num)]['state'] # Indicate the type of scan and port number
    result = ("[*] {host} tcp/{port} {state}".format(host=host_id, port=port_num, state=state))

    return result


if _name_ == '_main_':  # Runs the actual program
    try:
        user_args = argument_parser()
        host = user_args["host"]
        ports = user_args["ports"].split(",") # Make a list from port numbers
        for port in ports:
            print(nmap_scan(host, port))
    except AttributeError:
        print("Error, please provide the port")