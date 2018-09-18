from scapy.layers.inet import IP, UDP
from scapy.sendrecv import sr1
import ipaddress
import urllib3
import json


def ip_lookup(ip):
    http = urllib3.PoolManager()
    url_request = http.request('GET', 'http://freegeoip.net/json/'+ip)
    data_list = json.loads(url_request.data.decode('utf-8'))
    country = str(data_list['country_name'])
    city = str(data_list['city'])
    state = str(data_list['region_name'])
    zip_code = str(data_list['zip_code'])
    latitude = str(data_list['latitude'])
    longitude = str(data_list['longitude'])
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
    header = ('{:<2}''{:<12}''{:<18}''{:<15}''{:<14}''{:<13}''{:<10}''{:<12}''{:<14}'
              ).format('', '', "IP", "CITY", "STATE", "ZIP", "LAT", "LONG", "COUNTRY")
    print('\n', header)
    for i in range(1, 28):
        pkt = IP(dst=hostname, ttl=i) / UDP(dport=33434)
        reply = sr1(pkt, verbose=0)
        if reply is None:
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


def main():
    destination = input("Where are we headed...? ")
    trace_route(destination)


if __name__ == "__main__":
    main()
