import os
import sys
import socket
import ipaddress
import requests
import argparse
from scapy.layers.inet import IP, ICMP
from scapy.sendrecv import sr1


def options():
    parser = argparse.ArgumentParser(description="Geo-locate each hop along a traceroute")
    parser.add_argument('rhost', help="Remote machine ip or hostname")
    return parser.parse_args()


def ip_lookup(ip):
    url_request = requests.get('http://ip-api.com/json/' + ip)
    data_list = url_request.json()
    params = {'country': str(data_list['country']),
              'city': str(data_list['city']),
              'state': str(data_list['regionName']),
              'zip': str(data_list['zip']),
              'lat': str(data_list['lat']),
              'lon': str(data_list['lon'])}
    return params


def print_results(hops, reply, input_dict):
    try:
        output = ('{:<4}{:^12} {:<18}  {:<15} {:<14} {:<13} {:<10} {:<12} {:<14}'
                  ).format(hops, "hops away:",
                           info(reply),
                           info(input_dict['city']),
                           info(input_dict['state']),
                           info(input_dict['zip']),
                           info(input_dict['lat']),
                           info(input_dict['lon']),
                           info(input_dict['country'])
                           )
    except TypeError:
        priv_ip = input_dict
        output = '{:<2} {:^12} {:<18}'.format(hops, reply, priv_ip)
    print(output)


def trace_route(hostname):
    ip = str(socket.gethostbyname(hostname))
    print(hostname)
    print("IP ", ip)
    header = '{:<2} {:<12} {:<18} {:<15} {:<14} {:<13} {:<10} {:<12} {:<14}' \
        .format('', '', "IP", "CITY", "STATE", "ZIP", "LAT", "LON", "COUNTRY")
    print('\n', header)
    for i in range(1, 28):
        reply = sr1(IP(dst=sys.argv[1], ttl=i) / ICMP(id=os.getpid()), verbose=0)
        if reply is None:
            print("No Reply")
            break
        elif reply.src == ip:
            params = ip_lookup(reply.src) if not ipaddress.ip_address(reply.src) else "PRIV IP"
            print('\n', "We're here!", '\n', end=' ', flush=True)
            print_results(i, reply.src, params)
            break
        elif ipaddress.ip_address(reply.src).is_private:
            priv = "PRIV IP"
            print_results(i, reply.src, priv)
        else:
            params = ip_lookup(reply.src)
            print_results(i, reply.src, params)


def info(n):
    return n if n else ''


def main():
    args = options()
    trace_route(args.rhost)


if __name__ == "__main__":
    main()
