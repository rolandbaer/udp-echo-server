#!/usr/bin/env python3
"""
An UDP echo server and client that writes its own UDP and IPv4 headers
and allows to control udp and ip header fields.
"""
__version__ = "0.5.0"

import argparse
import ipaddress
import itertools
import logging
import socket
import struct
import sys
import time
from random import choice
from string import ascii_uppercase

logger = logging.getLogger(__name__)

# the buffer for receiving incoming messages
BUFFER_SIZE = 4096
# default port definition
CLIENT_PORT = 2010
SERVER_PORT = 2001
# dummy checksum, as the checksum is not mandatory (UDP) or calculated by the driver (IP)
DUMMY_CHECKSUM = 0
# Don't fragment flag set, other flags not set, fragment offset 0
DONT_FRAGMENT = 0x4000
FRAGMENTATION_ALLOWED = 0x0000
# Header legths
IP_HEADER_LENGTH_WORDS = 5
IP_HEADER_LENGTH = IP_HEADER_LENGTH_WORDS * 4
UDP_HEADER_LENGTH = 8
# IP Protocol version
IP_V4 = 4
# characters reserved for counter: #12345#Message
COUNTER_SIZE = 7

def send_and_receive_one(sender, listener, message, addr, ip_id, host_address):
    "Sends the message over the sender socket and waits for the response on the listener socket."
    send_udp_message(message, addr, ip_id, sender, host_address, args.cport)
    try:
        input_data, addr = listener.recvfrom(BUFFER_SIZE)
        logger.info("Received message back from %s: %s (%s bytes).", addr, input_data.decode(), len(input_data))
    except socket.timeout:
        logger.warning("Message never received back from %s: (%s).", addr, message)

def send_udp_message(message, addr, ip_id, sender, sender_address, sender_port):
    "Sends the message over the socket as an self-built udp/ip packet"
    message_encoded = message.encode()
    udp_msg = struct.pack("!HHHH"+str(len(message_encoded))+"s", sender_port, addr[1], UDP_HEADER_LENGTH + len(message_encoded), DUMMY_CHECKSUM, message_encoded)
    ip_header = struct.pack("!BBHHHBBHLL", IP_V4*16+IP_HEADER_LENGTH_WORDS, 0, IP_HEADER_LENGTH + len(udp_msg), ip_id, DONT_FRAGMENT if args.dontfragment else FRAGMENTATION_ALLOWED, 255, socket.IPPROTO_UDP, DUMMY_CHECKSUM, int(ipaddress.IPv4Address(sender_address)), int(ipaddress.IPv4Address(addr[0])))
    data = ip_header + udp_msg
    output_len = sender.sendto(data, addr)
    logger.info("Sent message to %s: %s (%s bytes, total %s bytes).", addr, message, len(message_encoded), output_len)

def receive_next(listener):
    "Repeatedly tries receiving on the given socket until some data comes in."
    logger.debug("Waiting to receive data...")
    while True:
        try:
            return listener.recvfrom(BUFFER_SIZE)
        except socket.timeout:
            logger.debug("No data received yet: retrying.")
            pass

def receive_and_send_one(listener, sender, ip_id):
    "Waits for a single datagram over the socket and echoes it back."
    input_data, addr = receive_next(listener)
    host_addr = listener.getsockname()
    message = input_data.decode()
    logger.info("Received message from %s: %s (%s bytes).", addr, message, len(input_data))
    send_udp_message(message, addr, ip_id, sender, host_addr[0], args.port)


def start_client(args):
    "Starts sending messages to the server."
    ip_id = time.time_ns() % 65536
    sender = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
    listener = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    listener.settimeout(1)  # seconds
    listener.bind((args.host, args.cport))
    if args.host == "0.0.0.0":
        hostname = socket.gethostname()
        host_address = socket.gethostbyname(hostname)
    else:
        host_address = args.host

    addr = (args.client, args.port) 
    message = ''.join(choice(ascii_uppercase) for i in range(args.size - COUNTER_SIZE))
    i = 1
    try:
        while i <= args.count:
            message_with_counter = "#{:05d}#{}".format(i % 100000, message)
            send_and_receive_one(sender, listener, message_with_counter, addr, ip_id, host_address)
            ip_id = (ip_id + 1) % 65536 
            i = i + 1
            if i <= args.count:
                time.sleep(args.interval)
    finally:
        logger.info("Shutting down.")
        sender.close()
        listener.close()


def start_server(args):
    "Runs the server."
    ip_id = time.time_ns() % 65536
    sender = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
    listener = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    listener.settimeout(5)  # seconds
    listener.bind((args.host, args.port))
    
    logger.info("Listening on %s:%s.", args.host, args.port)
    try:
        for i in itertools.count(1):
            receive_and_send_one(listener, sender, ip_id)
            ip_id = (ip_id + 1) % 65536 
            i = i + 1
    finally:
        logger.info("Shutting down.")
        sender.close()
        listener.close()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(__doc__, formatter_class = argparse.RawDescriptionHelpFormatter)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-C', '--client', help = 'Run in client mode, connect to the given HOST.', metavar = "HOST")
    group.add_argument('-S', '--server', help= 'Run in server mode.', action = 'store_true')
    group_client_server = parser.add_argument_group("For client and server")
    group_client_server.add_argument('-H', '--host', help = 'The host that the listener should listen on.', default = "0.0.0.0")
    group_client_server.add_argument('-p', '--port', help = 'Server port to listen on/connect to.', type = int, default = SERVER_PORT)
    group_client_server.add_argument('-d', '--dontfragment', help = 'Sets the don''t fragment flag (default: not set).', action = 'store_true')
    group_client = parser.add_argument_group("Only for client")
    group_client.add_argument('--cport', help = 'The port that the client will use to listen for the reply.', type = int, default = CLIENT_PORT)
    group_client.add_argument('-s', '--size', help = 'Size of udp data to be sent in payload  (default: 64).', type = int, default = 64)
    group_client.add_argument('-c', '--count', help = 'Number of udp packets to be sent. (default: 1)', type = int, default = 1)
    group_client.add_argument('-i', '--interval', help = 'Seconds between two sendings (default: 1 second).', type = int, default = 1)
    parser.add_argument('-v', '--verbose', help = "Increases the logging verbosity level.", action = 'count')
    parser.add_argument('-V', '--version', help = "Show version information and quit.", action='version', version='UDPecho version ' + __version__)
    if len(sys.argv) == 1:
        parser.print_help(sys.stderr)
        sys.exit(1)
    args = parser.parse_args()
    logging.basicConfig(level = logging.DEBUG if args.verbose else logging.INFO,
                        format = '%(asctime)s %(levelname)s %(message)s')
    if args.server:
        start_server(args)
    else:
        start_client(args)
