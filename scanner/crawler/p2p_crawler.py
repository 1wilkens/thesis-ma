#!/usr/bin/env python3

from collections import deque
from datetime import datetime
import time

from selectors import DefaultSelector, EVENT_READ, EVENT_WRITE
from socket import socket, AF_INET, SOCK_STREAM

from p2p_codec import decryptP2PMessage as decP2P
from p2p_utils import cryptRC4 as rc4

# Socket related
sel = DefaultSelector()
MAX_SOCKETCOUNT = 50
socketCount = 0
sockets = {}

# Crawling related
bots = []
msgPing = bytes()
rc4key = bytes()

def setup():
    global msgPing, rc4key

    with open("data/msg_crawler.bin.enc", "rb") as fp:
        msgPing = bytes(fp.read())

    with open("data/key_crawler.bin", "rb") as fp:
        rc4key = bytes(fp.read())

def teardown():
    global bots

    bots = sorted(bots, key=lambda x: x[1])
    for ip,botId in bots:
        print("{} {}".format(ip, botId))


    fileName = "results/crawler_{}.csv".format(datetime.now().strftime("%Y-%m-%d_%H-%M"))
    with open(fileName, "w") as fp:
        for ip,botId in bots:
            fp.write("{} {}\n".format(ip, botId))

def readIPs(filename):
    with open(filename, "r") as fp:
        return [l.strip().split(":") for l in fp]


def crawl():
    global socketCount, bots

    ips = deque(readIPs("data/ips.csv"))
    print("Crawling {} known bot IPs".format(len(ips)))

    while len(ips) > 0 or socketCount > 0:
        # Spin up MAX_SOCKETCOUNT sockets
        while len(ips) > 0 and socketCount < MAX_SOCKETCOUNT:
            (ip, port) = ips.popleft()
            sock = socket(AF_INET, SOCK_STREAM)
            sock.setblocking(False)
            sock.connect_ex((ip, int(port)))
            sockets[sock] = time.time()

            socketCount += 1
            sel.register(sock, EVENT_WRITE)

        if len(sel.get_map()) == 0:
            continue;

        # Select across all ready sockets
        for key, mask in sel.select(1):
            sock = key.fileobj
            if mask & EVENT_WRITE:
                # Socket is writable -> write msg
                try:
                    sock.sendall(msgPing)
                    sockets[sock] = time.time()
                    sel.modify(sock, EVENT_READ)
                except Exception as e:
                    # This fails if the ip is not routable so we have to silently ignore it
                    del sockets[sock]
                    sock.close()
                    socketCount -= 1
                    sel.unregister(sock)
            else:
                # Socket is readable -> read and validate response
                try:
                    with sock.makefile("rb") as fsock:
                        resp = fsock.read()
                    respMsg = decP2P(resp)
                    if respMsg is not None:
                        pong = rc4(respMsg[:4], rc4key)
                        if pong == b"PONG":
                            # We have an online bot -> log ip and botname
                            ip = sock.getpeername()[0]
                            botId = rc4(respMsg[8:], rc4key).decode(errors="ignore")
                            bots.append((ip, botId))
                except Exception as e:
                    print("recv", e, sock)
                    raise
                finally:
                    del sockets[sock]
                    sock.close()
                    socketCount -= 1
                    sel.unregister(sock)

        # Check if some sockets are trapped in a timeout
        now = time.time()
        for s, t in list(sockets.items()):
            if now - t > 30:
                del sockets[s]
                s.close()
                socketCount -= 1
                sel.unregister(s)


def main():
    print("Dridex L2 Crawler starting up..")
    setup()

    crawl()
    print("Crawl complete, found {} online L2 nodes".format(len(bots)))

    teardown()
    print("All done! Exiting..")


if __name__ == "__main__":
    main()
