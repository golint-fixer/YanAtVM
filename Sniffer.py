import ConfigParser
from optparse import OptionParser

import os, logging, socket
import pcapy, impacket, impacket.ImpactDecoder
from pcapy import findalldevs,open_live

ETHERNET_MAX_FRAME_SIZE = 1518
PROMISC_MODE = 0

class Packet(object):

    def __init__(self, bytes, sniffed_bytes, timestamp, proto_id, src_ip, tgt_ip, src_port, tgt_port, msgs):
        """ @brief Initialize data.
        """
        super(Packet, self).__init__()
        self.bytes = bytes
        self.sniffed_bytes = sniffed_bytes
        self.src_ip = src_ip
        self.tgt_ip = tgt_ip
        self.src_port = src_port
        self.tgt_port = tgt_port
        self.msgs = msgs
        self.timestamp = timestamp
        self.protocol = "unknown"
        try:
            if proto_id:
                if proto_id == socket.IPPROTO_TCP:
                    self.protocol = "TCP"
                elif proto_id == socket.IPPROTO_UDP:
                    self.protocol = "UDP"
                else:
                    self.protocol = PROTOCOLS[proto_id]
        except Exception, e:
            logging.error("Sniffer:start_sniffing : failed setting protocol. Error: %s" % str(e))
                    
    def __str__(self):
        return "Packet() : bytes:'%s', sniffed_bytes:'%s', timestamp:'%s', protocol:'%s', src_ip:'%s', tgt_ip:'%s', src_port:'%s', tgt_port:'%s', msgs:'%s'" % (str(self.bytes), str(self.sniffed_bytes), str(self.timestamp), str(self.protocol), str(self.src_ip), str(self.tgt_ip), str(self.src_port), str(self.tgt_port), str(self.msgs))


class Sniffer(object):
    """ @brief Class for sniffing and detecting packets.

        Requires python packages: pcapy (http://oss.coresecurity.com/projects/pcapy.html) and impacket (http://oss.coresecurity.com/projects/impacket.html)
    """

    def __init__(self, port_list):
        """ @brief Initialize data.

            @param List containing dest ports to sniff for.
        """
        super(Sniffer, self).__init__()
        self.port_list = port_list
        self.packets = []


    def get_interface(self):

        # Get the list of interfaces we can listen on
        ifs = findalldevs()

        # No interfaces found
        if len(ifs) == 0:
            raise RuntimeError, "Error: no available network interfaces, or you don't have enough permissions on this system."

        # A single interface was found
        if len(ifs) == 1:
            interface = ifs[0]

        # Multiple interfaces found
        else:
            print "Available network interfaces:"
            for i in xrange(len(ifs)):
                print '\t%i - %s' % (i + 1, ifs[i])
            print
            while 1:
                choice = raw_input("Choose an interface [0 to quit]: ")
                try:
                    i = int(choice)
                    if i == 0:
                        interface = None
                        break
                    interface = ifs[i-1]
                    break
                except Exception:
                    pass

        # Return the selected interface
        return interface    

    def do_sniffing(self, sniff_timeout = 1000):
        """ @brief Do sniffing and return results.

            @param device String that represents the device on which to capture packets.
            @param sniff_timeout Milliseconds during which packets are captured.
            @return List of packets that were retrieved.
        """
        p = None
        try:
            interface = self.get_interface()
            if interface:
                p = pcapy.open_live(interface, ETHERNET_MAX_FRAME_SIZE, PROMISC_MODE, sniff_timeout)
                logging.debug("Sniffer:start_sniffing : Listening on %s: net=%s, mask=%s" % (interface, p.getnet(), p.getmask()))
        except Exception, e:
            logging.error("Sniffer:start_sniffing : open_live() failed for device='%s'. Error: %s" % (interface, str(e)))

        if p:
            nr_packets = 0
            try:
                # maxcant is set to -1, so all packets are captured until the timeout
                nr_packets = p.dispatch(-1, self.receive_packets)
                logging.debug("Sniffer:start_sniffing : dispatch() returned for device='%s'. Packet count: %s" % (interface, str(nr_packets)))
            except Exception, e:
                logging.error("Sniffer:start_sniffing : dispatch() failed for device='%s'. Error: %s" % (interface, str(e)))
        
    def receive_packets(self, hdr, data):
        """ @brief Callback function for pcapy sniffer. """
        # these should be retrieved from IP packet or tcp/udp packet
        bytes = None
        sniffed_bytes = None
        timestamp = None
        proto_id = None
        src_ip = None
        tgt_ip = None
        src_port = None
        tgt_port = None
        msgs = [] # error msgs

        # try to decode the packet data using impacket
        decoder = impacket.ImpactDecoder.EthDecoder()
        eth_packet = None
        try:
            p = decoder.decode(data)
        except Exception, e:
            logging.error("Sniffer:receive_packets : impacket decoder raised exception: %s" % str(e))
            msgs.append(str(e))

        # get the details from the decoded packet data
        if p:
            # get details from IP packet
            try:
                src_ip = p.child().get_ip_src()
                tgt_ip = p.child().get_ip_dst()
                proto_id = p.child().child().protocol
            except Exception, e:
                logging.error("Sniffer:receive_packets : exception while parsing ip packet: %s" % str(e))
                msgs.append(str(e))
            # get details from TCP/UDP packet
            if proto_id:
                try:
                    if proto_id == socket.IPPROTO_TCP:
                        tgt_port = p.child().child().get_th_dport()
                        src_port = p.child().child().get_th_sport()
                    elif proto_id == socket.IPPROTO_UDP:
                        tgt_port = p.child().child().get_uh_dport()
                        src_port = p.child().child().get_uh_sport()
                except Exception, e:
                    logging.error("Sniffer:receive_packets : exception while parsing tcp/udp packet: %s" % str(e))
                    msgs.append(str(e))

        try:
            bytes = hdr.getlen() # the actual length of the ethernet packet
            sniffed_bytes = hdr.getcaplen() # the bytes that were captured by the sniffer (should be the same as bytes)
            # NOTE: bytes and sniffed_bytes should be equal since we're capturing ETHERNET_MAX_FRAME_SIZE
            # However, if the packet's size > ETHERNET_MAX_FRAME_SIZE => sniffed_bytes will be equal to ETHERNET_MAX_FRAME_SIZE, but bytes will be more
            if bytes != sniffed_bytes:
                logging.error("Sniffer:receive_packets : not all bytes were sniffed. Bytes = %s, sniffed = %s." % (str(bytes), str(sniffed_bytes)))
        except Exception, e:
            logging.error("Sniffer:receive_packets : impacket decoder raised exception: %s" % str(e))
            msgs.append(str(e))

        try:
            timestamp = hdr.getts()[0]
        except Exception, e:
            logging.error("Sniffer:receive_packets : failed getting timestamp from header. Exception: %s" % str(e))
            msgs.append(str(e))
        
        try:
            p_obj = Packet(bytes = bytes, sniffed_bytes = sniffed_bytes, timestamp = timestamp, proto_id = proto_id, src_ip = src_ip, tgt_ip = tgt_ip, src_port = src_port, tgt_port = tgt_port, msgs = msgs)
            self.packets.append(p_obj)
        except Exception, e:
            logging.error("Sniffer:receive_packets : failed constructing Packet object. Exception: %s" % str(e))


def parseCommandLineOptions (resultsetID=None):
   usage = "usage: %prog [options] "
   parser = OptionParser (usage)
   parser.add_option ("-s", "--srcIP", dest = "srcIP",
                      help = "")
   parser.add_option ("-d", "--desIP", dest = "desIP",
                      help = "")
   parser.add_option ("-p", "--protocal", dest = "protocal",
                      help = "", default = "udp")
   parser.add_option ("-o", "--port", dest = "port",
                      help = "")
   parser.add_option ("-t", "--testcase", dest = "tc",
                      help = "index the tc id for test cases.")   

   (options, args) = parser.parse_args ()
   return (options.srcIP, options.desIP, options.protocal, options.port, options.tc)

def runTC():
    (srcIP, desIP, protocal, port, tc)=parseCommandLineOptions() 
    ret = False
    s = Sniffer("m")
    try:
        if tc == '001':          
            #just capture the last 200 packet to validate, if you find it's not enough for the test case, just increase it.
            for num in range(0,200):
                s.do_sniffing()
                for p in s.packets:
                    print p
                    pack_src_ip = p.src_ip
                    pack_des_ip = p.tgt_ip
                    pack_port = str(p.src_port)
                    pack_protocol = p.protocol
                    if pack_src_ip and pack_des_ip and pack_port and pack_protocol:
                        if pack_src_ip.find(srcIP) != -1 and pack_des_ip.find(desIP) != -1 \
                        and pack_port.find(port) != -1 and pack_protocol.find(protocal) != -1:
                            ret = True   

        if tc == '002': 
            #just capture the last 200 packet to validate, if you find it's not enough for the test case, just increase it.
            for num in range(0,200):
                s.do_sniffing()
                for p in s.packets:
                    print p
                    pack_src_ip = p.src_ip
                    pack_des_ip = p.tgt_ip
                    if pack_src_ip and pack_des_ip:
                        if pack_src_ip.find(srcIP) != -1 and pack_des_ip.find(desIP) != -1:
                            print p.sniffed_bytes
                            ret = True   
    except Exception, e:
        logging.error("Run Sniffer TC Exception: %s" % str(e))
    else:
        pass
    finally:
        return ret

def main():
    print runTC()

if __name__ == "__main__":
    main()
