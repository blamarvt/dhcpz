import gevent
import logging
import gevent.socket as _socket

import dhcpz.util
import dhcpz.packet
import dhcpz.options

class DhcpServerListener(gevent.Greenlet):
    """
    Binds to a socket and listens for DHCP requests, calling 
    handle_packet on the specified handler class. Implemented as 
    a gevent Greenlet.
    """

    bufsize = 1500

    def __init__(self, ip_address, handler, logger=None):
        """
        @param ip_address: The IP address we're listening on
        @param handler: The class/instance to call handle_packet on
        """
        gevent.Greenlet.__init__(self)

        self.ip_address = ip_address
        self.handler = handler
        self.logger = logger or logging.getLogger(self.__class__.__name__)

        self.iface_name, self.ip_config = dhcpz.util.network_config()[ip_address]
        self._keepgoing = True

        self.sock = _socket.socket(_socket.AF_INET, _socket.SOCK_DGRAM)
        self.sock.setsockopt(_socket.SOL_SOCKET, _socket.SO_BROADCAST, 1)
        self.sock.setsockopt(_socket.SOL_SOCKET, _socket.SO_BINDTODEVICE, self.iface_name)
        self.sock.setsockopt(_socket.SOL_SOCKET, _socket.SO_REUSEADDR, 1)
        self.sock.bind(('', 67))

    def _run(self):
        while self._keepgoing:
            data, addr = self.sock.recvfrom(self.bufsize)
            packet = dhcpz.packet.DhcpPacket(data)
            response = self.handler.handle_packet(self, packet)
            if response:
                self.respond(response)

    def respond(self, packet):
        """
        Although technically we should be able to unicast a response, the DHCP
        specification allows for either a unicast or a broadcast response.

        @param packet: The DHCP packet to send back to the client
        """
        del packet["params"]
        self.sock.sendto(packet.pack(), ('255.255.255.255', 68))

    def stop(self):
        self._keepgoing = False
        self.kill()

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
        listener = self._listener_factory(ip_address, self.handler, self.logger)
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
