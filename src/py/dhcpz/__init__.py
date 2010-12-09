import logging, urllib

try:
    import json
except:
    import simplejson as json

from daemonhelper import Daemon, make_main
from dhcp.server import SimpleDhcpServer, NetworkConfig
from dhcp.packet import mac_ntoa
from dhcp.network import iter_ip_addresses

class DhcpzHandler(object):
    def __init__(self, url_template, logger=None, always_post=False):
        self.url_template = url_template
        self.logger = logger or logging.getLogger()
        self.always_post = always_post

    def _request_to_dict(self, mac_address, packet):
        return dict(mac=mac_ntoa(mac_address),
                message_type=packet.msgtype_name,
                requested_ip=packet.requested_ip, 
                client_identifier=packet.client_identifier,
                vendor_class_identifier=packet.vendor_class_identifier,
                server_identifier=packet.server_identifier)

    def acquire_config(self, mac_address, packet):
        template_options = self._request_to_dict(mac_address, packet)

        url = self.url_template % template_options
        if self.always_post:
            response = urllib.urlopen(url, urllib.urlencode(template_options))
        else:
            response = urllib.urlopen(url)

        headers = response.info()
        content_type = headers.get('content-type').split(";")[0].strip()
        if content_type in ("application/json", "text/plain", None):
            data = tuple(json.load(response))
        else:
            raise ValueError("unknown mimetype %r" % content_type)

        return NetworkConfig.from_dict(data)


    def release_config(self, mac_address, packet):
        self.logger.info("Releasing network configuration for client %s" % mac_ntoa(mac_address))
        template_options = self._request_to_dict(mac_address, packet)
        url = self.url_template
        urllib.urlopen(url, urllib.urlencode(template_options)).read()
    
    def handle_conflict(self, mac_address, conflicting_ip_address, _):
        self.logger.warning("IP conflict reported for %s by client %s" % (conflicting_ip_address, mac_address))

def _str_to_bool(value):
    value = value.lower()
    if value in ("yes", "true", "t", "y", "1"):
        return True
    elif value in ("no", "false", "f", "n", "0"):
        return False
    else:
        raise ValueError("value %r should be yes or no" % value)

class DhcpzDaemon(Daemon):
    name = "dhcpz"
    description = "DHCP server with a ReSTful HTTP backend"

    def handle_prerun(self):
        url_template = self.config("dhcpz", "url", "http://localhost/%(mac)s")
        always_post = self.config("dhcpz", "always_post", "yes", transform=_str_to_bool)
        handler = DhcpzHandler(url_template, self.logger, always_post)
        
        self._server = SimpleDhcpServer(handler)
        
        listen_ips = self.config("dhcpz", "listen", None)
        if listen_ips is None:
            listen_ips = iter_ip_addresses()
        else:
            listen_ips = listen_ips.split(",")

        for listen_ip in listen_ips:
            self.logger.info("listening on %s" % listen_ip)
            self._server.listen(listen_ip)

    def handle_run(self):
        self._server.run()

    def handle_stop(self):
        self._server.stop()

main = make_main(DhcpzDaemon)

if __name__ == "__main__":
    main()

