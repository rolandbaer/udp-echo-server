# udpecho server and client

A Python 3 UDP echo server and client for testing connections.

## Usage

udpecho uses raw sockets for sending the packages. Therefore you need administrative
privileges to run the client and server. On Unix Systems you request them with `sudo`,
on Windows Systems you sould open a command line with Administrator rights.

### Server

```
$ sudo python3 udpecho.py --server
```

### Client

```
$ sudo python3 udpecho.py --client $IP --count 5 --size 1200 --interval 2
```
### Parameters

For a complete list of the parameters call udpecho.py with the parameter -h or --help

## Hints

If you want to define the pattern yourself but don't want to search the values
in the ascii table, you can use the following trick:
```
$ sudo python3 udpecho.py --client 127.0.0.1 --pattern `echo "MyMessage" | tr -d '\n' | xxd -ps`
```
The tr command removes the newline from the message and the xxd command
converts the message to the hexadecimal representation as needed by the
--pattern parameter

## History

The code is based on the udp echo server by Marshall Polaris (https://github.com/mqp/udp-echo-server) and the additons by Umakant Kulkarni (https://github.com/UmakantKulkarni/udp-echo-server).

As the development derived significant from the basic implementation the project was separated from its predecessors. 