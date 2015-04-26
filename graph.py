#!/usr/bin/python

"""
Sniffs on the WiFi network and generates a graph showing the communication
between the devices, including information about the announced SSIDs.

Author: Jacek Wielemborek, licensed under WTFPL
"""

import subprocess
import sys
from StringIO import StringIO
from lxml import etree
from collections import defaultdict

class Wifibacon(object):

    def __init__(self):
        self.seen = defaultdict(lambda: defaultdict(int))
        self.announces = defaultdict(list)

    def parse_packet(self, packet_str):
        """
        Parses a <packet></packet> XML string, returning information about the
        sender, receiver and the announced networks. If sender or receiver is
        not known, returns '?' in its place. If SSID is not announced, None
        is returned.
        """
        d = {}
        ssid = None
        for line in packet_str.split("\n"):
            if '"wlan.ra"' in line or '"wlan.ta"' in line \
                    or '"wlan.sa"' in line:
                field = etree.fromstring(line)
                if 'ff:ff:ff:ff:ff:ff' in field.get('showname'):
                    continue
                name = field.get('name')
                d[name] = field.get('showname').split(': ')[1]
                d[name] = d[name].replace(' ', '\\n')
            if '"wlan_mgt.ssid"' in line:
                field = etree.fromstring(line)
                if ssid is not None and field.get('show') != ssid:
                    sys.stderr.write("WTF: SSID: %s vs %s" % (repr(ssid),
                                     repr(field.get('show'))))
                ssid = field.get('show')
        if d.get('wlan.ta') != d.get('wlan.sa'):
            sys.stderr.write("WTF: sa=%s != ra=%s" %
                             (repr(d.get('wlan.ta')), repr(d.get('wlan.ta'))))
        to_mac = d.get('wlan.ra', '?') \
            if d.get('wlan.ra') != 'ffffffffffff' else '?'
        from_mac = d.get('wlan.ta', '?') or d.get('wlan.sa', '?')
        return from_mac, to_mac, ssid

    def handle_packet(self, from_mac, to_mac, ssid):
        """
        Handles information about noticing a given packet in order to prepare
        it for reporting.
        """
        self.seen[from_mac][to_mac] += 1
        if ssid:
            found = self.announces[from_mac]
            if len(found) != 0 and ssid not in found:
                sys.stderr.write('WTF: two ssids: %s, %s, %s\n' %
                    (from_mac, ssid, found))
            if ssid not in found:
                self.announces[from_mac] += [ssid]

    def print_report(self):
        """
        Prints out a DOT file based on the gathered information.
        """
        print("strict digraph {")
        for k1 in self.seen:
            for k2 in self.seen[k1]:
                #if 'k1' == '?' or 'k2' == '?':
                #    continue
                if k1 in self.announces:
                    k1 += '\\nAnnounces: ' + ',\\n'.join(self.announces[k1])
                if k2 in self.announces:
                    k2 += '\\nAnnounces: ' + ',\\n'.join(self.announces[k2])
                print('"%s" -> "%s";' % (k1, k2))
        print("}")

    def read_from_file(self, infile, outfile=None):
        """
        Reads the output of tshark -T pdml. If outfile is specified,
        the information is also saved to the outfile.
        """
        packet = StringIO()
        while True:
            line = infile.readline()
            if line == '':
                break
            packet.write(line)
            if outfile:
                outfile.write(line)
            if '</packet>' in line:
                packet_str = packet.getvalue()
                from_mac, to_mac, ssid = self.parse_packet(packet_str)
                self.handle_packet(from_mac, to_mac, ssid)
                packet = StringIO()

def main():

    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--infile')
    parser.add_argument('--outfile')
    args = parser.parse_args()

    if args.outfile:
        outfile = open(args.outfile, "w")
    else:
        outfile = None

    p = None
    if args.infile:
        infile = open(args.infile)
    else:
        p = subprocess.Popen("tshark -i wlp3s0 -I -y IEEE802_11_RADIO -T pdml",
                             shell=True, stdout=subprocess.PIPE)
        infile = p.stdout

    w = Wifibacon()
    try:
        w.read_from_file(infile, outfile)
    finally:
        w.print_report()

if __name__ == '__main__':
    main()
