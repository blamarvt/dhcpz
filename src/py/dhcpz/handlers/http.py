"""
dhcpz.handlers.http
"""

from dhcpz.handlers.base import DhcpHandler

class HttpDhcpHandler(DhcpHandler):
    def handle_discover(self, packet):
        pass

    def handle_decline(self, packet):
        pass

    def handle_request(self, packet):
        pass

    def handle_release(self, packet):
        pass
