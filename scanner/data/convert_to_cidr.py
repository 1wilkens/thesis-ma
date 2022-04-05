#!/usr/bin/env

import sys

def main():
    sums = {}
    for i in range(1, 31):
        sum_ = 2**i
        sums[sum_] = 32 - i

    for l in sys.stdin:
        split = l.split("|")
        val = int(split[1])
        if val in sums:
            print("{}/{}".format(split[0], sums[val]))
        else:
            valb = list(reversed(bin(val)))
            exp = 32
            exps = []
            for d in valb:
                if d == '1':
                    exps.append(exp)
                exp -= 1

            exps.sort()

            i1, i2, i3, i4 = list(map(int, split[0].split(".")))
            ip_sum = (i1 << 24) + (i2 << 16) + (i3 << 8) + i4
            for e in exps:
                ip_sum_str = "{}.{}.{}.{}".format(ip_sum >> 24, (ip_sum >> 16 & 0xFF), (ip_sum >> 8) & 0xFF, ip_sum & 0xFF)
                print("{}/{}".format(ip_sum_str, e))
                ip_sum += 2**(32-e)

if __name__ == "__main__":
    main()
