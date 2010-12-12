"""
dhcpz.packet
"""
import dpkt.dhcp as dhcp

import dhcpz.options

class DhcpPacket(dhcp.DHCP):
    """
    DhcpPacket(dhcp.DHCP    

    This packet abstraction is a subclass of the dpkt.dhcp.DHCP class. `dpkt`
    provides serialization and unserialization for DHCP packets, while this
    class provides a convenient way to make DHCP responses, retrieve readable
    values from DHCP packets, and easily set new values in DHCP packets.

    Simple Example:
        my_packet = DhcpPacket(network_data)
        print my_packet['mac'] # Will print readable MAC format
        print my_packet['ip']  # Will print client IP in dotted quad format

    CAUTION: `dpkt` expects a very specific type of data for it's headers. 
             Always give `dpkt` unpacked integers when integers are expected,
             and always give IP addresses in unpacked integer form when setting
             header values. When setting 'opts' or DHCP options, always use
             packed byte values. This is taken care of by the 'isheader' option
             when calling to_octets and from_octets.
    """
    def make_response(self, msgtype, opts=None):
        """
        Convenience function for creating a reply from an existing DHCP packet.

        @param msgtype: DHCP message type (from dpkt.dhcp)
        @param opts: dict(opt1=val1, opt2=val2...)
        """
        resp = self.__class__()
        
        # Add all given options
        opts = opts and dict(opts) or {}
        for optcode, optvalue in opts.iteritems():
            resp[optcode] = optvalue
        
        # Copy certain headers/options into new packet
        for name in ("htype", "hlen", "hops", "xid", "secs", "flags", "mac"):
            resp[name] = self[name]
        
        # Turn packet into a response type
        resp["op"] = dhcp.DHCP_OP_REPLY
        resp["msgtype"] = msgtype

        return resp

    def to_dict(self):
        """
        Display this DHCP packet as a python dict().
        """
        retval = {}
        for key in self:
            retval[key] = self[key]
        return retval

    def __getitem__(self, optcode):
        """
        Convenience function for accessing pieces of the DHCP packet. For
        a complete list of options that a DHCP packet can/should have, refer
        to RFC 2131 and/or run options.py from a shell.

        @param optcode: The name of the value requested. For example, this 
                        might be 'op', 'hlen', etc. if you want to get a 
                        standard DHCP header, or this might be 'next-server',
                        'leasetime', etc. if you want to get a DHCP option.
        """
        isheader, optdef = dhcpz.options.get_definition(optcode)
        if isheader:
            value = getattr(self, optdef.optcode)
            value = optdef.typedef.from_octets(value, isheader=isheader)
        else:
            value = None
            for itemcode, itemvalue in self.opts:
                if itemcode == optdef.optcode:
                    value = optdef.typedef.from_octets(itemvalue, isheader=isheader)
                    break
        return value

    def __setitem__(self, optcode, value):
        """
        @param optcode: The name of the value you're setting. For example, this 
                        might be 'op', 'hlen', etc. if you want to set a 
                        standard DHCP header, or this might be 'next-server',
                        'leasetime', etc. if you want to set a DHCP option.
        @param value: The value of the header/option
        """
        isheader, optdef = dhcpz.options.get_definition(optcode)
        if value is None:
            value = getattr(optdef.typedef, "default", None)
        else:
            value = optdef.typedef.to_octets(value, isheader=isheader)

        if isheader:
            setattr(self, optdef.optcode, value)
        else:
            self.opts = filter(lambda v: v[0] != optdef.optcode, self.opts)
            if value is not None:
                self.opts += ((optdef.optcode, value),)

    def __delitem__(self, optcode):
        """
        @param optcode: The name of the value you're deleting. For example, this 
                        might be 'op', 'hlen', etc. if you want to remove a 
                        standard DHCP header, or this might be 'next-server',
                        'leasetime', etc. if you want to remove a DHCP option.
        """
        self[optcode] = None

    def __iter__(self):
        """
        Iterator through all DHCP packet headers and options.
        """
        for hdrname in self.__hdr_fields__:
            yield hdrname
        for optcode, _ in self.opts:
            optdef = dhcpz.options.get_definition(optcode)[1]
            yield optdef.aliases[0]


