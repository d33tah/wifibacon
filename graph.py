#!/usr/bin/python

import subprocess
import sys
from StringIO import StringIO
from lxml import etree
from collections import defaultdict

def handle_packet(packet_str):
    lines = packet_str.split("\n")
    d = {}
    ssid = None
    for line in lines:
        if '"wlan.ra"' in line or '"wlan.ta"' in line or '"wlan.sa"' in line:
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
    #if d.get('wlan.ta') != d.get('wlan.sa'):
    #    print("Interesting: %s" % d)
    to_mac = d.get('wlan.ra', '?') \
        if d.get('wlan.ra') != 'ffffffffffff' else '?'
    from_mac = d.get('wlan.ta', '?') or d.get('wlan.sa', '?')
    return from_mac, to_mac, ssid

def read_from_file(infile, outfile=None):
    announces = defaultdict(list)
    try:
        packet = StringIO()
        while True:
            line = infile.readline()
            if line == '':
                break
            packet.write(line)
            if outfile:
                outfile.write(line)
            if '</packet>' in line:
                from_mac, to_mac, ssid = handle_packet(packet.getvalue())
                d[from_mac][to_mac] += 1
                if ssid:
                    found = announces[from_mac]
                    if len(found) != 0 and ssid not in found:
                        sys.stderr.write('WTF: two ssids: %s, %s, %s\n' %
                            (from_mac, ssid, found))
                    if ssid not in found:
                        announces[from_mac] += [ssid]
                packet = StringIO()
    except KeyboardInterrupt:
        print("strict digraph {")
        for k1 in d:
            for k2 in d[k1]:
                #if 'k1' == '?' or 'k2' == '?':
                #    continue
                if k1 in announces:
                    k1 += '\\nAnnounces: ' + ',\\n'.join(announces[k1])
                if k2 in announces:
                    k2 += '\\nAnnounces: ' + ',\\n'.join(announces[k2])
                print('"%s" -> "%s";' % (k1, k2))
        print("}")

if __name__ == '__main__':
    # TODO: stderr to /dev/null?
    p = subprocess.Popen("tshark -i wlp3s0 -I  -y IEEE802_11_RADIO -T pdml",
                         shell=True, stdout=subprocess.PIPE)

    d = defaultdict(lambda: defaultdict(int))
    if len(sys.argv) > 1:
        f = open(sys.argv[1], "w")
    else:
        f = None
    read_from_file(p.stdout, f)
