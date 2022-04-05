#!/usr/bin/env python3

from collections import deque
from datetime import datetime
import time

from selectors import DefaultSelector, EVENT_READ, EVENT_WRITE
from socket import socket, AF_INET, SOCK_STREAM

from p2p_codec import decryptP2PMessage as decryptP2P, cryptRC4 as rc4

# Socket related
sel = DefaultSelector()
MAX_SOCKETCOUNT = 512
socketCount = 0
sockets = {}

# Scan related
infectedIPs = {}
ports = [443, 8443 #], 3443, 4443] #, 444, 448, 843, 943, 1443, 80, 8080, 8000, 8888]
msgCheckme = bytes()
rc4key = bytes()
outputFd = None

def setup():
    global msgCheckme, rc4key, outputFd

    with open("data/msg_scanner.bin.enc", "rb") as fp:
        msgCheckme = bytes(fp.read())

    with open("data/key_scanner.bin", "rb") as fp:
        rc4key = bytes(fp.read())

    outputFd = open(
        "results/ripe/scanner_{}.csv".format(datetime.now().strftime("%Y-%m-%d_%H-%M")), "w")

def teardown():
    global outputFd

    outputFd.close()

def logInfection(ip, p, payload, msg):
    global outputFd, infectedIPs

    # Add to set
    infectedIPs[ip] = (p, msg)
    # Write to results
    outputFd.write("{}:{} ({} --/-- {})\n".format(ip, p, payload, msg))
    outputFd.flush()

    # Save payload separately
    #with open("results/ripe/payload_{}_{}.bin".format(ip, p), "wb") as fp:
    #    fp.write(payload)


def readIPs(filename):
    with open(filename, "r") as fp:
        return [l.strip() for l in fp]


def scanPort(p):
    global socketCount

    ips = deque(readIPs("data/zmap_ripe_{}.csv".format(p)))
    print("Scanning port {} ({} IP addresses)".format(p, len(ips)))

    while len(ips) > 0 or socketCount > 0:
        # Spin up MAX_SOCKETCOUNT sockets
        while len(ips) > 0 and socketCount < MAX_SOCKETCOUNT:
            ip = ips.popleft()
            if ip in infectedIPs:
                # Skip ips which are already known to be infected
                continue
            sock = socket(AF_INET, SOCK_STREAM)
            sock.setblocking(False)
            sock.connect_ex((ip, p))
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
                    sock.sendall(msgCheckme)
                    sockets[sock] = time.time()
                    sel.modify(sock, EVENT_READ)
                except:
                    del sockets[sock]
                    sock.close()
                    socketCount -= 1
                    sel.unregister(sock)
            else:
                # Socket is readable -> read and validate response
                try:
                    with sock.makefile("rb") as fsock:
                        resp = fsock.read()
                    respMsg = decryptP2P(resp)
                    if respMsg is not None:
                        # We have an infection
                        ip = sock.getpeername()[0]
                        status = rc4(respMsg[:4], rc4key)
                        if status == b"0404":
                            print("Found infected host @{}:{}".format(ip, p))
                        else:
                            print("Found echo server @{}:{}".format(ip, p))
                        logInfection(ip, p, resp, respMsg)
                except:
                    pass
                finally:
                    del sockets[sock]
                    sock.close()
                    socketCount -= 1
                    sel.unregister(sock)

        # Check if some sockets are trapped in a timeout
        now = time.time()
        for s, t in list(sockets.items()):
            if now - t > 20:
                del sockets[s]
                s.close()
                socketCount -= 1
                sel.unregister(s)

    print("Finished scanning port", p)
    if len(infectedIPs) > 0:
        print(len(infectedIPs), "total infected IPs until now")


def main():
    print("Dridex L2 Scanner starting up..")
    setup()

    print("Starting scan")
    for p in ports:
        scanPort(p)
    print("Scan complete, found {} infected IPs".format(len(infectedIPs)))

    teardown()
    print("All done! Exiting..")


if __name__ == "__main__":
    main()
