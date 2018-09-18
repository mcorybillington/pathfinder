import socket
from scapy.layers.inet import IP, UDP
from scapy.sendrecv import sr1
import ipaddress
import requests
import sys


def ip_lookup(ip):
    url_request = requests.get('http://ip-api.com/json/'+ip)
    data_list = url_request.json()
    country = str(data_list['country'])
    city = str(data_list['city'])
    state = str(data_list['region_name'])
    zip_code = str(data_list['zip_code'])
    latitude = str(data_list['lat'])
    longitude = str(data_list['lon'])
    return country, city, state, zip_code, latitude, longitude


def print_results(hops, reply, city, state, zip_code, lat, lon, country):
    output = ('{:<2}''{:^12}''{:<18}''{:<15}''{:<14}''{:<13}''{:<10}''{:<12}''{:<14}'
              ).format(hops, "hops away:",
                       info(reply),
                       info(city),
                       info(state),
                       info(zip_code),
                       info(lat),
                       info(lon),
                       info(country)
                       )
    print(output)


def trace_route(hostname):
    ip = str(socket.gethostbyname(hostname))
    print(hostname)
    print("IP ", ip)
    header = ('{:<2}''{:<12}''{:<18}''{:<15}''{:<14}''{:<13}''{:<10}''{:<12}''{:<14}'
              ).format('', '', "IP", "CITY", "STATE", "ZIP", "LAT", "LONG", "COUNTRY")
    print('\n', header)
    for i in range(1, 28):
        pkt = IP(dst=ip, ttl=i) / UDP(dport=33434)
        print("sent")
        reply = sr1(pkt, verbose=0)
        print("received")
        if reply is None:
            print("noreply")
            break
        elif reply.type == 3:
            country, city, state, zip_code, latitude, longitude = ip_lookup(reply.src)
            print('\n', "We're here!", '\n', end=' ', flush=True)
            print_results(i, reply.src, city, state, zip_code, latitude, longitude, country)
            break
        else:
            ipaddress.ip_address(reply.src)
            if ipaddress.ip_address(reply.src).is_private:
                priv = "Priv IP"
                print_results(i, reply.src, priv, priv, priv, priv, priv, priv)
            else:
                country, city, state, zip_code, latitude, longitude = ip_lookup(reply.src)
                print_results(i, reply.src, city, state, zip_code, latitude, longitude, country)


def info(n):
    answer = n if n else ''
    return answer


def main(ip_arg):
    trace_route(ip_arg)


if __name__ == "__main__":
    main(sys.argv[1])
