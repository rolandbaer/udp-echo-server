#!/usr/bin/env python3
"""
An UDP echo server and client that writes its own UDP and IPv4 headers
and allows to control udp and ip header fields.
"""
__version__ = "0.8.1"

import argparse
import ipaddress
import itertools
import logging
import math
import platform
import socket
import statistics
import struct
import sys
import time
from dataclasses import dataclass
from random import choice, randint
from string import ascii_uppercase

LOGGER = logging.getLogger(__name__)

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

@dataclass
class Sockets:
    "Container of sending and listening sockets"
    def __init__(self, sender: socket.socket, listener: socket.socket):
        self.sender = sender
        self.listener = listener

@dataclass
class ProtocolData:
    "Container for protocol data"
    def __init__(self, ip_id: int, address: str, port: int, dontfragment: bool):
        self.ip_id = ip_id
        self.address = address
        self.port = port
        self.dontfragment = dontfragment

def is_windows():
    return platform.system().lower().startswith('win')

def sec_to_ms_with_us(seconds: float):
    return math.floor((seconds * 1000 * 1000) + 0.5) / 1000

def send_and_receive_one(sockets: Sockets, message: str, addr: tuple, protocol_data: ProtocolData, quiet: bool):
    """Sends the message over the sender socket and waits for the response on the listener socket.
    Returns the roundtrip time or 0 if no response was received."""

    started = time.perf_counter()
    send_udp_message(message, addr, sockets.sender, protocol_data, quiet)
    try:
        input_data, addr = sockets.listener.recvfrom(BUFFER_SIZE)
        timespan = time.perf_counter() - started
        if not quiet:
            LOGGER.info("Received message back from %s in %s ms: %s (%s bytes).",
                        addr, sec_to_ms_with_us(timespan), input_data.decode(), len(input_data))
        return timespan
    except socket.timeout:
        LOGGER.warning("Message never received back from %s: (%s).", addr, message)
        return 0.0

def send_udp_message(message: str, addr: tuple, sender: socket.socket, protocol_data: ProtocolData, quiet: bool):
    "Sends the message over the socket as an self-built udp/ip packet"
    message_encoded = message.encode()
    if is_windows():
        LOGGER.debug("windows (udp)")
        output_len = sender.sendto(message_encoded, addr)
    else:
        LOGGER.debug("other (raw)")
        udp_msg = struct.pack("!HHHH"+str(len(message_encoded))+"s",
                          protocol_data.port, addr[1], UDP_HEADER_LENGTH + len(message_encoded),
                          DUMMY_CHECKSUM, message_encoded)
        ip_header = struct.pack("!BBHHHBBHLL",
                                IP_V4*16+IP_HEADER_LENGTH_WORDS,
                                0,
                                IP_HEADER_LENGTH + len(udp_msg),
                                protocol_data.ip_id,
                                DONT_FRAGMENT if protocol_data.dontfragment else FRAGMENTATION_ALLOWED,
                                255,
                                socket.IPPROTO_UDP,
                                DUMMY_CHECKSUM,
                                int(ipaddress.IPv4Address(protocol_data.address)),
                                int(ipaddress.IPv4Address(addr[0])))
        data = ip_header + udp_msg
        output_len = sender.sendto(data, addr)
    if not quiet:
        LOGGER.info("Sent message to %s: %s (%s bytes, total %s bytes).", addr, message,
                    len(message_encoded), output_len)

def receive_next(listener: socket.socket):
    "Repeatedly tries receiving on the given socket until some data comes in."
    LOGGER.debug("Waiting to receive data...")
    while True:
        try:
            return listener.recvfrom(BUFFER_SIZE)
        except socket.timeout:
            LOGGER.debug("No data received yet: retrying.")

def receive_and_send_one(sockets: Sockets, ip_id: int, port: int, dontfragment: bool, quiet: bool):
    "Waits for a single datagram over the socket and echoes it back."
    input_data, addr = receive_next(sockets.listener)
    host_addr = sockets.listener.getsockname()
    message = input_data.decode()
    if not quiet:
        LOGGER.info("Received message from %s: %s (%s bytes).", addr, message, len(input_data))
    protocol_data = ProtocolData(ip_id, host_addr[0], port, dontfragment)
    send_udp_message(message, addr, sockets.sender, protocol_data, quiet)

def get_local_ip(target: str):
    "Gets the IP address of the interfaces used to connect to the target."
    temp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    temp_socket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    temp_socket.connect((target, 0))
    my_ip = temp_socket.getsockname()[0]
    temp_socket.close()
    return my_ip

def start_client(arguments):
    "Starts sending messages to the server."
    ip_id = randint(0, 65535)
    listener = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    if is_windows():
        sender = listener
    else:
        sender = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
    listener.settimeout(1)  # seconds
    listener.bind((arguments.host, arguments.cport))
    if arguments.host == "0.0.0.0":
        host_address = get_local_ip(arguments.client)
        LOGGER.debug("Clients IP: %s", host_address)
    else:
        host_address = arguments.host

    addr = (arguments.client, arguments.port)
    message = ''.join(choice(ascii_uppercase) for i in range(arguments.size - COUNTER_SIZE))
    i = 1
    received = 0
    timespans = []
    try:
        while i <= arguments.count:
            message_with_counter = "#{:05d}#{}".format(i % 100000, message)
            sockets = Sockets(sender, listener)
            protocol_data = ProtocolData(ip_id, host_address, arguments.cport,
                                         arguments.dontfragment)
            timespan = send_and_receive_one(sockets, message_with_counter, addr, protocol_data, arguments.quiet)
            if timespan > 0:
                received = received + 1
                timespans.append(timespan)
            ip_id = (ip_id + 1) % 65536
            i = i + 1
            if i <= arguments.count:
                time.sleep(arguments.interval)
    finally:
        if i > 1:
            LOGGER.info("%s packets transmitted, %s received, %s%% loss", i - 1, received, 100 * (i - 1 - received) / (i - 1))
        if len(timespans) > 0:
            LOGGER.info("  min/avg/max: %s/%s/%s ms", sec_to_ms_with_us(min(timespans)), sec_to_ms_with_us(statistics.mean(timespans)), sec_to_ms_with_us(max(timespans)))
        LOGGER.info("Shutting down.")
        sender.close()
        listener.close()


def start_server(arguments):
    "Runs the server."
    ip_id = randint(0, 65535)
    if is_windows():
        sender = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    else:
        sender = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
    listener = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    listener.settimeout(5)  # seconds
    listener.bind((arguments.host, arguments.port))

    LOGGER.info("Listening on %s:%s.", arguments.host, arguments.port)
    try:
        for i in itertools.count(1):
            sockets = Sockets(sender, listener)
            receive_and_send_one(sockets, ip_id, arguments.port, arguments.dontfragment, arguments.quiet)
            ip_id = (ip_id + 1) % 65536
            i = i + 1
    except KeyboardInterrupt:
        LOGGER.debug("<CTRL>-C received, ending listener")
    finally:
        LOGGER.info("Shutting down.")
        sender.close()
        listener.close()

def init_parser(__doc__, __version__, CLIENT_PORT, SERVER_PORT):
    PARSER = argparse.ArgumentParser(__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    GROUP = PARSER.add_mutually_exclusive_group(required=True)
    GROUP.add_argument('-C', '--client', help='Run in client mode, connect to the given HOST.',
                       metavar="HOST")
    GROUP.add_argument('-S', '--server', help='Run in server mode.', action='store_true')
    GROUP_CLIENT_SERVER = PARSER.add_argument_group("For client and server")
    GROUP_CLIENT_SERVER.add_argument('-H', '--host',
                                     help='The host that the listener should listen on.',
                                     default="0.0.0.0")
    GROUP_CLIENT_SERVER.add_argument('-p', '--port', help='Server port to listen on/connect to.',
                                     type=int, default=SERVER_PORT)
    GROUP_CLIENT_SERVER.add_argument('-d', '--dontfragment',
                                     help='Sets the don''t fragment flag (default: not set).',
                                     action='store_true')
    GROUP_CLIENT_SERVER.add_argument('-q', '--quiet', 
                                     help='Quiet output. Only the start message and the summary are displayed',
                                     action='store_true')
    GROUP_CLIENT = PARSER.add_argument_group("Only for client")
    GROUP_CLIENT.add_argument('--cport',
                              help='The port that the client will use to listen for the reply.',
                              type=int, default=CLIENT_PORT)
    GROUP_CLIENT.add_argument('-s', '--size',
                              help='Size of udp data to be sent in payload  (default: 64).',
                              type=int, default=64)
    GROUP_CLIENT.add_argument('-c', '--count',
                              help='Number of udp packets to be sent. (default: 1)',
                              type=int, default=1)
    GROUP_CLIENT.add_argument('-i', '--interval',
                              help='Seconds between two sendings (default: 1 second).',
                              type=int, default=1)
    PARSER.add_argument('-v', '--verbose', help="Increases the logging verbosity level.",
                        action='count')
    PARSER.add_argument('-V', '--version', help="Show version information and quit.",
                        action='version', version='UDPecho version ' + __version__)
                        
    return PARSER

if __name__ == "__main__":
    PARSER = init_parser(__doc__, __version__, CLIENT_PORT, SERVER_PORT)
    if len(sys.argv) == 1:
        PARSER.print_help(sys.stderr)
        sys.exit(1)
    ARGS = PARSER.parse_args()
    logging.basicConfig(level=logging.DEBUG if ARGS.verbose else logging.INFO,
                        format='%(asctime)s %(levelname)s %(message)s')
    if is_windows():
        if ARGS.dontfragment:
            LOGGER.error("Argument 'dontfragment' is not supported on windows systems.")
            sys.exit(2)
    if ARGS.server:
        start_server(ARGS)
    else:
        start_client(ARGS)
