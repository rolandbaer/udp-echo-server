# udpecho server and client

A Python 3 UDP echo server and client for testing connections.

## Usage

### Server

```
$ sudo python3 udpecho.py --server
```

### Client

```
$ sudo python3 udpecho.py --client $IP --count 5 --size 1200 --interval 2
```

## History

The code is based on the udp echo server by Marshall Polaris (https://github.com/mqp/udp-echo-server) and the additons by Umakant Kulkarni (https://github.com/UmakantKulkarni/udp-echo-server).

As the development derived significant from the basic implementation the project was separated from its predecessors. 