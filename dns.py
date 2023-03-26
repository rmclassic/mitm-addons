import asyncio
import ipaddress
import socket
import requests
from collections.abc import Callable
from collections.abc import Iterable

from mitmproxy import dns
import mitmproxy
from mitmproxy.proxy import mode_specs

import logging
import json

class DnsShash:
    dnsmap = {}

    async def server_connect(self, data: mitmproxy.proxy.server_hooks.ServerConnectionHookData):
        if data.server.address in self.dnsmap:
            data.server.address = (self.dnsmap[data.server.address[0]], data.server.address[1])
        
        url = 'https://104.16.248.249/dns-query'
        client = requests.session()
        params = {
            'name': data.server.address[0],
            'type': 'A',
        }

        headers = {
            'accept': 'application/dns-json',
            'host': 'cloudflare-dns.com'
        }
        ae = client.get(url, params=params, headers=headers, verify=False)
        xx = json.loads(ae.content)
        if xx['Status'] == 0:
            self.dnsmap[data.server.address] = xx["Answer"][0]['data']
            data.server.address = (xx["Answer"][0]['data'], data.server.address[1])

addons = [DnsShash()]