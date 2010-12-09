import logging

from gevent import Greenlet, socket
import dpkt.dhcp as dhcp
import netifaces

import options

DHCP_SERVER_PORT = 67

class DhcpPacket(dhcp.DHCP):
	def make_response(self, msgtype, opts=None):
		resp = self.__class__()
		
		# Add all given options
		opts = opts and dict(opts) or {}
		for optcode, optvalue in opts.iteritems():
			resp[optcode] = optvalue
		
		# Copy certain headers/options into new packet
		for name in ("htype", "hlen", "hops", "xid", "secs", "flags", "chaddr"):
			resp[name] = self[name]
		
		# Turn packet into a response type
		resp["op"] = dhcp.DHCP_OP_REPLY
		resp["msgtype"] = msgtype

		return resp

	def debug(self):
		for key, value in self.to_dict().iteritems():
			yield "%s: %s" % (key, value)

	def to_dict(self):
		retval = {}
		for key in self:
			retval[key] = self[key]
		return retval

	def __getitem__(self, optcode):
		isheader, optdef = options.get_definition(optcode)
		if isheader:
			value = getattr(self, optdef.optcode)
		else:
			value = None
			for itemcode, itemvalue in self.opts:
				if itemcode == optdef.optcode:
					value = itemvalue
					break
		if isheader and getattr(optdef.typedef, "dpkt_header_skip", None):
			return value
		else:
			return optdef.typedef.from_octets(value)

	def __setitem__(self, optcode, value):
		isheader, optdef = options.get_definition(optcode)
		if value is None:
			value = getattr(optdef.typedef, "default", None)
		elif not isheader and not getattr(optdef.typedef, "dpkt_header_skip", None):
			value = optdef.typedef.to_octets(value)

		if isheader:
			setattr(self, optdef.optcode, value)
		else:
			self.opts = filter(lambda v: v[0] == optdef.optcode, self.opts)
			if value is not None:
				self.opts.append((optdef.optcode, value))

	def __delitem__(self, optcode):
		self[optcode] = None

	def __iter__(self):
		for hdrname in self.__hdr_fields__:
			yield hdrname
		for optcode, _ in self.opts:
			optdef = options.get_definition(optcode)[1]
			yield optdef.aliases[0]


class DhcpServerListener(Greenlet):
	bufsize = 1500

	def __init__(self, ip_address, handler):
		Greenlet.__init__(self)
		self.ip_address = ip_address
		self.handler = handler

		self.iface_name, self.ip_config = _ip_to_net_conf(self.ip_address)
		self._keepgoing = True

		self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
		self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
		self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, self.iface_name)
		self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
		self.sock.bind(('0.0.0.0', DHCP_SERVER_PORT))
	
	def _run(self):
		while self._keepgoing:
			data, addr = self.sock.recvfrom(self.bufsize)
			packet = DhcpPacket(data)
			self.handler.handle_packet(self, packet, addr)

	def stop(self):
		self._keepgoing = False

	def __repr__(self):
		return "<%s on %s (%s)>" % (self.__class__.__name__, self.ip_address, self.iface_name)

class DhcpServer(object):
	_listener_factory = DhcpServerListener

	def __init__(self, handler, logger=None):
		self.handler = handler
		self.logger = logger or logging.getLogger(self.__class__.__name__)
		self._listeners = []
		self._running = False

	def listen(self, ip_address):
		listener = self._listener_factory(ip_address, self.handler)
		self._listeners.append(listener)
		if self._running:
			self._launch_listener(listener)

	def run(self):
		self._running = True
		map(self._launch_listener, self._listeners)
		for listener in self._listeners:
			listener.join()

	def stop(self):
		self._running = False
		for listener in self._listeners:
			listener.stop()

	def _launch_listener(self, listener):
		self.logger.info("listening on %s" % listener.ip_address)
		listener.start()

class HttpDhcpHandler(object):
	def __init__(self, logger=None):
		self.logger = logger or logging.getLogger(self.__class__.__name__)

	def handle_packet(self, listener, packet, address):
		self.logger.debug("%r %r %r" % (listener, packet, address))
		self.logger.debug(repr(packet.get_option(dhcp.DHCP_OPT_MSGTYPE)))

	def handle_discover(self, packet):
		pass

	def handle_decline(self, packet):
		pass

	def handle_request(self, packet):
		pass

	def handle_release(self, packet):
		pass
	
	_dispatch = {
			dhcp.DHCPDISCOVER : handle_discover,
			dhcp.DHCPDECLINE : handle_decline,
			dhcp.DHCPREQUEST : handle_request,
			dhcp.DHCPRELEASE : handle_release,
			}

class DebugDhcpHandler(object):
	def handle_packet(self, listener, packet, address):
		print "Received on listener %r from %r:" % (listener, address)
		print '\n'.join(["\t" + line for line in packet.debug()])

# Helpers for mapping ip addresses to netowkr interfaces

_ip_config_cache = None

def _ip_config_cache_init():
	global _ip_config_cache # horrible, I know -VonHollen
	if _ip_config_cache is not None:
		return

	_ip_config_cache = {}
	for iface_name in netifaces.interfaces():
		iface = netifaces.ifaddresses(iface_name)
		if netifaces.AF_INET not in iface:
			continue
		for ip_config in iface[netifaces.AF_INET]:
			ip_config_addr = ip_config['addr']
			_ip_config_cache[ip_config_addr] = iface_name, ip_config

def _ip_to_net_conf(ip_address):
	_ip_config_cache_init()
	return _ip_config_cache[ip_address]

def _iter_ip_addresses():
	_ip_config_cache_init()
	return filter(lambda ip: not ip.startswith('127'), _ip_config_cache)


# Main method for creating a test listener

def dhcpz_debug_main():
	import sys
	logging.basicConfig(stream=sys.stderr, level=logging.DEBUG)
	handler = DebugDhcpHandler()
	server = DhcpServer(handler)
	for ip in _iter_ip_addresses():
		server.listen(ip)
	server.run()

if __name__ == "__main__":
	dhcpz_debug_main()
