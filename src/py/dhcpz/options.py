#!/usr/bin/python

import struct
import socket

from uuid import UUID

from dpkt.dhcp import *

# Global options database

option_list = []
optalias_to_def = {}


# Map of optcodes to headers for treating headers like options

header_list = []
hdralias_to_def = {}


# Primary public methods

def get_definition(optcode):
    optcode = _normalize_option_alias(optcode)
    hdrdef = hdralias_to_def.get(optcode)
    if hdrdef is not None:
        return True, hdrdef

    optdef = optalias_to_def.get(optcode)
    if optdef is not None:
        return False, optdef

    raise KeyError(optcode)

def value_to_log(optcode, value):
    return get_definition(optcode).typedef.to_log(value)

def octets_to_log(optcode, value):
    try:
        optdef = get_definition(optcode)
        return "%s = %s" % (optdef, optdef.typedef.to_log(optdef.typedef.from_octets(value, isheader=isheader)))
    except KeyError:
        return "unknown(%d) = %r" % (optcode, value)


# Helpers for to/from octets methods

class PassThruType(object):
    def from_octets(self, value, isheader=False):
        return value

    def to_octets(self, value, isheader=False):
        return value

    def __str__(self):
        return "pass-thru"

class IntType(object):
    dpkt_header_skip = True

    def __init__(self, fmt):
        self._struct = struct.Struct("!" + fmt)

    def from_octets(self, value, isheader=False):
        if isheader:
            return value
        else:
            return self._struct.unpack(value)[0]

    def to_octets(self, value, isheader=False):
        if isheader:
            return value
        else:
            return self._struct.pack(value)

    def to_log(self, value):
        return "%d" % value

    def __len__(self):
        return self._struct.size

    def __str__(self):
        return "uint%d" % (len(self) * 8)

class Ipv4Type(object):
    dpkt_header_skip = True

    def from_octets(self, value, isheader=False):
        if isheader:
            v = "%08x" % value
            return "%i.%i.%i.%i" % (int(v[0:2],16),int(v[2:4],16),int(v[4:6],16),int(v[6:8],16))
        else:
            return socket.inet_ntoa(value)

    def to_octets(self, value, isheader=False):
        if isheader:
            v = value.split(".")
            return int("%02x%02x%02x%02x" % (int(v[0]),int(v[1]),int(v[2]),int(v[3])),16)        
        else:
            return socket.inet_aton(value)
    
    def to_log(self, value):
        return str(value)

    def __len__(self):
        return 4
    
    def __str__(self):
        return "ipv4-address"

class ListType(object):
    def __init__(self, itemtype):
        self._itemtype = itemtype
        self._itemlen = len(self._itemtype)

    def from_octets(self, value, isheader=False):
        while value:
            item, value = value[:self._itemlen], value[self._itemlen:]
            yield self._itemtype.from_octets(item, isheader=isheader)

    def to_octets(self, value, isheader=False):
        retval = []
        for item in value:
            retval.append(self._itemtype.to_octets(item, isheader=isheader))
        return ''.join(retval)
    
    def to_log(self, value):
        return ",".join(map(self._itemtype.to_log, value))

    def __str__(self):
        return "list<%s>" % self._itemtype

class StringType(object):
    def from_octets(self, value, isheader=False):
        return value

    def to_octets(self, value, isheader=False):
        return value
    
    def to_log(self, value):
        return repr(value)

    def __str__(self):
        return "string"

class BytesType(object):
    def from_octets(self, value, isheader=False):
        return value

    def to_octets(self, value, isheader=False):
        return value

    def to_log(self, value):
        return "0x" + ''.join(["%02X" % ord(octet) for octet in value])

    def __str__(self):
        return "octets"

class UuidType(object):
    def from_octets(self, value, isheader=False):
        value = value[1:]
        return UUID(bytes=value)

    def to_octets(self, value, isheader=False):
        return struct.pack("B", 0) + value.bytes

    def to_log(self, value):
        return repr(value)

    def __str__(self):
        return "uuid"

class EnumType(IntType):
    def __init__(self, value_to_name, fmt="B"):
        IntType.__init__(self, fmt)
        self.value_to_name = value_to_name

    def from_octets(self, value, isheader=False):
        value = IntType.from_octets(self, value, isheader=isheader)
        return self.value_to_name.get(value, value)

    def to_octets(self, value, isheader=False):
        retcode = None
        for code, name in self.value_to_name.iteritems():
            if value in (code, name):
                retcode = code
                break

        if retcode is None:
            raise KeyError(value)

        return IntType.to_octets(self, retcode, isheader=isheader)

    def to_log(self, value):
        if not isinstance(value, basestring):
            value = self.value_to_name.get(value, value)
        return repr(value)

    def __str__(self):
        return "enum {%s}" % ", ".join(["%d=%s" % v for v in self.value_to_name.iteritems()])

class StructType(object):
    def __init__(self, *typedefs):
        self.typedefs = typedefs
        assert self.typedefs

    def from_octets(self, value, isheader=False):
        for typedef in self.typedefs[:-1]:
            # each item requires size
            length = len(typedef)
            item, value = value[:length], value[length:]
            yield typedef.from_octets(item, isheader=isheader)
        
        # last item doesn't need size
        yield self.typedefs[-1].from_octets(value, isheader=isheader)

    def to_octets(self, value, isheader=False):
        retval = []
        for typedef, item in zip(self.typedefs, value):
            retval.append(typedef.to_octets(item, isheader=isheader))
        return ''.join(retval)

    def to_log(self, value):
        retval = []
        for typedef, item in zip(self.typedefs, value):
            retval.append(typedef.to_log(item))
        return "(%s)" % ", ".join(retval)

    def __str__(self):
        return "struct <%s>" % ", ".join(map(str, self.typedefs))

class MacType(object):
    def from_octets(self, value, sep=":", isheader=False):
        value = value[0:6] #TODO: Better solution? Logging? More? -B
        return sep.join(["%02X" % ord(c) for c in value])

    def to_octets(self, value, isheader=False):
        retval = []
        value = value.replace(":", "")
        while value:
            octet, value = value[:2], value[2:]
            retval.append(chr(int(octet, 16)))
        return ''.join(retval)

    def to_log(self, value):
        return str(value)

    def __str__(self):
        return "mac-address"

    def __len__(self):
        return 6

class VariableNullPadding(object):
    def __init__(self, typedef, padlen):
        self.typedef = typedef
        self.padlen = padlen

    def from_octets(self, value, isheader=False):
        value = value.rstrip("\0")
        return self.typedef.from_octets(value, isheader=isheader)

    def to_octets(self, value, isheader=False):
        value = self.typedef.to_octets(value, isheader=isheader)
        value = value[:self.padlen]
        value += "\0" * (self.padlen - len(value))
        return value

    def to_log(self, value):
        return self.typedef.to_log(value)

    def __str__(self):
        return str(self.typedef) + ("[%d]" % self.padlen)


class NullPadding(object):
    def __init__(self, typedef, padlen):
        self.typedef = typedef
        self.padlen = padlen
        self.pad = "\0" * self.padlen

    def from_octets(self, value, isheader=False):
        return self.typedef.from_octets(value[:self.padlen], isheader=isheader)

    def to_octets(self, value, isheader=False):
        return self.typedef.to_octets(value, isheader=isheader) + self.pad

    def to_log(self, value):
        return self.typedef.to_log(value)

    def __str__(self):
        return str(self.typedef) + ("[%d]" % self.padlen)


uint8 = IntType("B")
uint16 = IntType("H")
uint32 = IntType("I")
ipv4 = Ipv4Type()
string = StringType()
octets = BytesType()
mac = MacType()

# Misc helpers

def _normalize_option_alias(optalias):
    if isinstance(optalias, basestring):
        optalias = optalias.lower().strip().replace("-", "")
    return optalias

# Helpers for defining options

class OptionDefinition(object):
    def __init__(self, optcode, typedef, aliases):
        self.optcode = optcode
        self.typedef = typedef
        self.aliases = aliases
        assert self.aliases

    def __cmp__(self, other):
        return cmp(self.optcode, other.optcode)

    def __str__(self):
        return self.aliases[0]

    def debug_aligned(self):
        aliases = "".join([", alias %s" % alias for alias in self.aliases[1:]])
        yield "%24s (code %s, type %s%s)" % (self.aliases[0], self.optcode, self.typedef, aliases)

def define_option(optcode, typedef, *aliases):
    optdef = OptionDefinition(optcode, typedef, aliases)
    option_list.append(optdef)
    optalias_to_def[optcode] = optdef
    for alias in aliases:
        alias = _normalize_option_alias(alias)
        optalias_to_def[alias] = optdef

def define_header(hdrname, typedef, *aliases):
    aliases = (hdrname,) + aliases
    hdrdef = OptionDefinition(hdrname, typedef, aliases)
    header_list.append(hdrdef)
    for alias in aliases:
        alias = _normalize_option_alias(alias)
        hdralias_to_def[alias] = hdrdef

# Common DHCP options from RFC 2132

define_option(DHCP_OPT_NETMASK, ipv4, "netmask", "subnet")
define_option(DHCP_OPT_ROUTER, ListType(ipv4), "router", "routers", "gateway", "gateways")
define_option(DHCP_OPT_DNS_SVRS, ListType(ipv4), "dns", "domain-name-server", "domain-name-servers")
define_option(DHCP_OPT_HOSTNAME, string, "hostname", "host", "name")
define_option(DHCP_OPT_DOMAIN, string, "domain", "domainname")
define_option(DHCP_OPT_MTUSIZE, uint16, "mtu", "mtusize")
define_option(DHCP_OPT_BROADCASTADDR, ipv4, "broadcast", "broadcastaddr")
define_option(DHCP_OPT_VENDOR_ID, string, "vendor", "vendor-id")
define_option(DHCP_OPT_REQ_IP, ipv4, "requested-ip", "requested", "request")
define_option(DHCP_OPT_LEASE_SEC, uint32, "leasetime", "lease")
define_option(DHCP_OPT_MSGTYPE, uint8, "msgtype", "messagetype")
define_option(DHCP_OPT_SERVER_ID, ipv4, "serverid", "serverip")
define_option(DHCP_OPT_PARAM_REQ, ListType(uint8), "paramreq", "param", "params")
define_option(DHCP_OPT_MESSAGE, string, "message", "msg")
define_option(DHCP_OPT_MAXMSGSIZE, uint16, "maxmsgsize", "maxsize")
define_option(DHCP_OPT_RENEWTIME, uint32, "renewtime", "renew")
define_option(DHCP_OPT_REBINDTIME, uint32, "rebindtime", "rebind")
define_option(DHCP_OPT_VENDSPECIFIC, octets, "vendorspecific")
define_option(DHCP_OPT_CLIENT_ID, octets, "clientid", "client")


# Intel PXE Options from RFC 4578

client_arch_map = {
        0 : "intel-x86-pc",
        1 : "nec/pc98",
        2 : "efi-itanium",
        3 : "dec-alpha",
        4 : "arc-x86",
        5 : "intel-lean-client",
        6 : "efi-ia32",
        7 : "efi-bc",
        8 : "efi-xscale",
        9 : "efi-x86-64",
        }

define_option(93, EnumType(client_arch_map, "H"), "client-architecture", "client-arch", "arch")
define_option(94, StructType(EnumType({1:"undi"}), uint8, uint8), "network-interface-id", "nic-id")
define_option(97, UuidType(), "client-machine-id")


# RFC 3004

define_option(77, octets, "user-class")


# Pxelinux options (http://syslinux.zytor.com/wiki/index.php/PXELINUX)

define_option(208, octets, "pxelinux-magic")
define_option(209, string, "pxelinux-configfile", "pxelinux-config")
define_option(210, string, "pxelinux-pathprefix", "pxelinux-prefix")
define_option(211, string, "pxelinux-reboottime", "pxelinux-reboot")


# GPXE/Etherboot options

define_option(175, octets, "gpxe-options")


# Make option definitions for all headers so we can work with both using the same iterface

define_header("op", EnumType({1:"request", 2:"reply"}))
define_header("hrd", uint8, "htype", "hardware-type")
define_header("hln", uint8, "hlen", "hardware-length")
define_header("hops", uint8)
define_header("xid", uint32, "transaction-id")
define_header("secs", uint16, "seconds")
define_header("flags", uint16)
define_header("ciaddr", ipv4, "client-ip")
define_header("yiaddr", ipv4, "ip", "ip-address")
define_header("siaddr", ipv4, "next-server")
define_header("giaddr", ipv4, "relay", "relay-ip")
define_header("chaddr", mac, "mac", "client-mac")
define_header("sname", VariableNullPadding(string, 64), "server-name")
define_header("file", VariableNullPadding(string, 128), "filename")
define_header("magic", uint32)

# Exposed client database via script execution

def main():
    print "Required headers:"
    for hdrdef in header_list:
        print '\n'.join(hdrdef.debug_aligned())

    print "Supported options:"
    option_list.sort()
    for optdef in option_list:
        print '\n'.join(optdef.debug_aligned())

if __name__ == "__main__":
    main()
