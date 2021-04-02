#!/usr/bin/env python3
"""
An UDP echo server and client that writes its own UDP and IPv4 headers
and allows to control udp and ip header fields.
"""
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
# Header legths
IP_HEADER_LENGTH_WORDS = 5
IP_HEADER_LENGTH = IP_HEADER_LENGTH_WORDS * 4
UDP_HEADER_LENGTH = 8
# IP Protocol version
IP_V4 = 4

def send_and_receive_one(sender, listener, message, addr, ip_id):
    "Sends the message over the sender socket and waits for the response on the listener socket."
    send_udp_message(message, addr, ip_id, sender)
    try:
        input_data, addr = listener.recvfrom(BUFFER_SIZE)
        logger.info("Received message back from %s: %s (%s bytes).", addr, input_data.decode(), len(input_data))
    except socket.timeout:
        logger.warning("Message never received back from %s: (%s).", addr, message)

def send_udp_message(message, addr, ip_id, sender):
    "Sends the message over the socket as an self-built udp/ip packet"
    message_encoded = message.encode()
    udp_msg = struct.pack("!HHHH"+str(len(message_encoded))+"s", CLIENT_PORT, addr[1], UDP_HEADER_LENGTH + len(message_encoded), DUMMY_CHECKSUM, message_encoded)
    ip_header = struct.pack("!BBHHHBBHLL", IP_V4*16+IP_HEADER_LENGTH_WORDS, 0, IP_HEADER_LENGTH + len(udp_msg), ip_id, DONT_FRAGMENT, 255, socket.IPPROTO_UDP, DUMMY_CHECKSUM, 0x7f000001, int(ipaddress.IPv4Address(addr[0])))
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
    message = input_data.decode()
    logger.info("Received message from %s: %s (%s bytes).", addr, message, len(input_data))
    send_udp_message(message, addr, ip_id, sender)


def start_client(args):
    "Starts sending messages to the server."
    ip_id = time.time_ns() % 65536
    sender = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
    listener = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    listener.settimeout(1)  # seconds
    listener.bind(('127.0.0.1', CLIENT_PORT))
    addr = (args.host, args.port) 
    message = ''.join(choice(ascii_uppercase) for i in range(args.size))
    i = 1
    try:
        while i <= args.count:
            send_and_receive_one(sender, listener, message, addr, ip_id)
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
    parser.add_argument('--server', '-S', help= 'Run in server mode.', action = 'store_true')
    parser.add_argument('--host', help = 'The host that the client should connect to.', default = "127.0.0.1")
    parser.add_argument('--port', help = 'The port that the client should connect to.', type = int, default = SERVER_PORT)
    parser.add_argument('--verbose', '-v', help = "Increases the logging verbosity level.", action = 'count')
    parser.add_argument('--count', '-c', help = 'Number of udp packets to be sent', type = int, default = 1)
    parser.add_argument('--size', '-s', help = 'size of udp data to be sent in payload', type = int, default = 64)
    parser.add_argument('--interval', '-i', help = 'Interval of sending in seconds', type = int, default = 1)
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