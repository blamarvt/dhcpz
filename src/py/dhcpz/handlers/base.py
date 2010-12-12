"""
dhcpz.handlers.base
"""

import dpkt.dhcp as dhcp

class DhcpHandler(object):
    """
    Handlers are the work-horse classes of dhcpz. All logic for handling
    the flow of DHCP packets happens in a handler.
    """

    def __init__(self, logger=None):
        """
        @param logger: Logger to use for all logging in this class
        """
        self.logger = logger or logging.getLogger(self.__class__.__name__)

    def handle_packet(self, listener, packet):
        """
        @param listener: The class handling all communications
        @param packet: The incoming packet
        """ 
        try:
            return self._dispatch[packet["msgtype"]](self, packet)
        except KeyError:
            self.logger.debug("Unknown message type encountered: %d" % packet.msgtype)

    def handle_discover(self, packet):
        """
        DHCPDISCOVER can result in DHCPOFFER
        
        If you're going to return DHCPOFFER to the client, you MUST have:
            -IP address lease time
            -Server identifier
        
        If you're going to return DHCPOFFER to the client, you MAY have:
            -File or sname fields
            -Vendor class information
            -Any other field

        If you're going to return DHCPOFFER to the client, you MUST NOT have:
            -The requested IP address
            -Parameter request list
            -Client identifier
            -Maximum message size

        @param packet: The incoming packet from a client
        """
        response = packet.make_response(dhcp.DHCPOFFER, {
            'ip'          : '169.254.10.10',
            'next-server' : '169.254.0.1',
            'leasetime'   : 3600,
            'serverid'    : '169.254.0.1',
        })
        return response

    def handle_request(self, packet):
        """
        DHCPREQUEST can result in DHCPACK, or DHCPNAK.
        
        If you're going to return DHCPACK, to the client, you MUST have:
            -Server identifier
            -Ip address lease time
        
        If you're going to return DHCPACK, to the client, you MAY have:
            -File or sname fields
            -Vendor class information
            -Any other field

        If you're going to return DHCPACK, to the client, you MUST NOT have:
            -The requested IP address
            -Parameter request list
            -Client identifier
            -Maximum message size

        @param packet: The incoming packet from a client
        """
        response = packet.make_response(dhcp.DHCPACK, {
            'ip'          : '169.254.10.10',
            'next-server' : '169.254.0.1',
            'leasetime'   : 3600,
            'serverid'    : '169.254.0.1',
        })
        return response

    def handle_decline(self, packet):
        pass

    def handle_release(self, packet):
        pass
    
    _dispatch = {
            dhcp.DHCPDISCOVER : handle_discover,
            dhcp.DHCPDECLINE : handle_decline,
            dhcp.DHCPREQUEST : handle_request,
            dhcp.DHCPRELEASE : handle_release,
            }



