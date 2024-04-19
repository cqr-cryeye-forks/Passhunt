# -*- coding: utf-8 -*-
# !/usr/bin/env python3
"""
This tool allows you to search for default credentials for routers, network devices,
    web applications and more.

# python passhunt.py -t joomla.afganii.fun
# python passhunt.py -t testphp.vulnweb.com

Source idea of passhunt:
    Author: Viral Maniar
    Twitter: https://twitter.com/maniarviral
    Github: https://github.com/Viralmaniar
    LinkedIn: https://au.linkedin.com/in/viralmaniar
"""
import json
from argparse import ArgumentParser

import bs4 as bs
import nmap3
import requests

requests.packages.urllib3.disable_warnings()
SERVICE_URL = "https://cirt.net"
VENDORS_URL = f"{SERVICE_URL}/passwords?vendor="

HEADERS = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0',
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
    'Accept-Language': 'en-US,en;q=0.5',
    'Connection': 'keep-alive',
    'Upgrade-Insecure-Requests': '1',
    'Sec-Fetch-Dest': 'document',
    'Sec-Fetch-Mode': 'navigate',
    'Sec-Fetch-Site': 'none',
    'Sec-Fetch-User': '?1',
}


def check_service():
    try:
        resp = requests.get(SERVICE_URL, headers=HEADERS, verify=False)
        if resp.status_code != 200:
            raise Exception
    except Exception:
        print('cirt.net service is not available, exiting...')
        exit(1)
    else:
        print('cirt.net service is available, continue...')


def parse_vendors(data: str) -> list:
    soup = bs.BeautifulSoup(data, 'html.parser')
    vendors = soup.find_all('td')
    return [v.text.lower() for v in vendors if v]


def get_vendors() -> list:
    resp = requests.get(VENDORS_URL, headers=HEADERS, verify=False)
    if resp.status_code != 200:
        print("failed to retrieve vendors from cirt.net, exiting...")
        exit(1)

    return parse_vendors(resp.content.decode('utf-8'))


def cli(parser: ArgumentParser):
    parser.add_argument(
        '-t', '--target',
        required=True,
        help="Target for passhunt"
    )
    parser.add_argument(
        '-o', '--output',
        default='output.json',
        help="Output file path (json format)"
    )
    return parser.parse_args()


def parse_nmap_result(services: dict) -> list:
    for service in services.values():
        if service.get('ports'):
            services = service.get('ports')
            break
    # probably, can produce ['', '', '', ...], but that's okay
    return [s.get('service', {}).get('product', '').lower() for s in services if s]


def run_nmap(host: str) -> list:
    try:
        nmap = nmap3.Nmap()
        result = nmap.nmap_version_detection(host)
        # result = [
        #     {
        #         "cpe": [
        #             {
        #                 "cpe": "cpe:/o:linux:linux_kernel"
        #             }
        #         ],
        #         "port": "80",
        #         "protocol": "tcp",
        #         "service": {
        #             "conf": "10",
        #             "extrainfo": "Ubuntu",
        #             "method": "probed",
        #             "name": "http",
        #             "ostype": "Linux",
        #             "product": "nginx",
        #             "version": "1.14.0"
        #         }
        #     },
        #     {
        #         "cpe": [
        #             {
        #                 "cpe": "cpe:/o:linux:linux_kernel"
        #             }
        #         ],
        #         "port": "443",
        #         "protocol": "tcp",
        #         "service": {
        #             "conf": "10",
        #             "extrainfo": "Ubuntu",
        #             "method": "probed",
        #             "name": "http",
        #             "ostype": "Linux",
        #             "product": "nginx",
        #             "tunnel": "ssl",
        #             "version": "1.14.0"
        #         }
        #     },
        #     {
        #         "cpe": [
        #             {
        #                 "cpe": "cpe:/o:linux:linux_kernel"
        #             }
        #         ],
        #         "port": "2000",
        #         "protocol": "tcp",
        #         "service": {
        #             "conf": "10",
        #             "extrainfo": "Ubuntu Linux; protocol 2.0",
        #             "method": "probed",
        #             "name": "ssh",
        #             "ostype": "Linux",
        #             "product": "OpenSSH",
        #             "version": "7.6p1 Ubuntu 4ubuntu0.3"
        #         }
        #     }
        # ]
        return parse_nmap_result(result)

    except Exception as e:
        print(e)
        exit(1)


def parse_vendor_info(data: str) -> list:
    output = []
    soup = bs.BeautifulSoup(data, 'html.parser')
    table = soup.find_all('table')
    for item in table:
        info = {}
        tr = item.find_all('tr')[1:]
        try:
            for tr_ in tr:
                tds = tr_.find_all('td')
                info.update({
                    tds[0].text.lower().strip().replace(" ", "_"): tds[1].text.strip()
                })
            output.append(info)
        except Exception:
            continue

    return output


def get_info(vendor: str) -> list:
    resp = requests.get(f"{VENDORS_URL}{vendor}", headers=HEADERS, verify=False)
    if resp.status_code != 200:
        print("failed to retrieve vendors from cirt.net, exiting...")
        exit(1)

    return parse_vendor_info(resp.content.decode('utf-8'))


def main():
    parser = ArgumentParser()
    args = cli(parser)
    check_service()
    vendors = get_vendors()
    services = run_nmap(args.target)
    print(f"Found services: {services}")
    output = []
    for s in services:
        if s in vendors:
            output.extend(get_info(s))

    print(f"Output: {output}")
    with open(args.output, 'w') as f:
        json.dump(output, f, indent=2)


if __name__ == "__main__":
    main()
