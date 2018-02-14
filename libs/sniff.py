#!/usr/bin/env python
# -*- coding: utf-8 -*-

import re
import os
import time
import Queue
import socket
import gevent
import MySQLdb as mysql
import datetime
import argparse
import traceback
from commands import getoutput
import dns.resolver
from gevent import monkey;monkey.patch_all()
from scapy.all import sr1, IP, UDP, DNS, DNSQR, DNSRR, sniff
from core import LogsHelper

class PassiveDNS(object):
    def __init__(self):
        self.conf = LogsHelper().load_all_config()

        self.passive_domain = set()
        self.dnslogsQueueList = Queue.Queue()
        self.ip_re = re.compile('(?<![\.\d])(?:\d{1,3}\.){3}\d{1,3}(?![\.\d])')
        self.myResolver = dns.resolver.Resolver()
        self.badDNS = '1.1.1.1'
        try:
            result = self.myResolver.query('tr3jer.google.com')
            self.badDNS = result[0].address.split('.')
            self.badDNS.pop(-1)
            self.badDNS = '.'.join(self.badDNS)
        except:
            pass
        try:

            db_ip = self.conf['database']['ip']
            db_port = self.conf['database']['port']
            db_username = self.conf['database']['username']
            db_password = self.conf['database']['password']
            dbname = self.conf['database']['dbname']
            self.conn = mysql.connect(user=db_username, passwd=db_password, host=db_ip, db=dbname, port=int(db_port))

            self.cur = self.conn.cursor()

            try:
                sql = "select domain from dnslogs"
                self.cur.execute(sql)
                for i in self.cur.fetchall():
                    self.passive_domain.add(i[0])
            except Exception, e:
                print '\033[91m' + '\033[1m' + '[+].... Pull Domain From Database Error ....[+]' + '\033[0m'
        except mysql.Error, e:
            print '\033[91m' + '\033[1m' + '[+].... Login mysql failed,check your config ....[+]' + '\033[0m'

    def get_first_interface(self):
        ips = {}
        for i in range(0, 5):
            ip = getoutput('ipconfig getifaddr en' + str(i))
            if len(ip) > 4:
                ips['en' + str(i)] = ip
        if len(ips.keys()) ==0:
            print "[*]No Interface can bed used!"
            exit(0)
        else:
            return ips.keys()[0]

    def save_mysql(self):
        print '[*]\033[91m' + '\033[1m', "Everything is Oj8k...", '\033[0m'

        # save all the times.
        while True:

            while not self.dnslogsQueueList.empty():
                try:
                    record_log = self.dnslogsQueueList.get()

                    domain = record_log['domain'].strip()
                    domain_ip = record_log['domain_ip'].strip()
                    port = record_log['port']
                    dns_client_ip = record_log['dns_client_ip'].strip()
                    dns_server_ip = record_log['dns_server_ip'].strip()
                    record_time = record_log['record_time']

                    try:
                        pam = (domain, domain_ip, port, dns_client_ip, dns_server_ip, record_time)
                        sql = "insert into dnslogs (`domain`, `domain_ip`, `port`, `dns_client_ip`, `dns_server_ip`, `record_time`) values(%s,%s,%s,%s,%s,%s)"
                        self.cur.execute(sql, pam)
                        self.conn.commit()
                    except Exception,e:
                        print e
                        print '\033[91m' + '\033[1m' + '[+].... Save failed check your mysql status....[+]' + '\033[0m'
                        time.sleep(10)
                except:
                    print "[!]write file fails."
            time.sleep(5)


    def value_sniper(self,arg1):
        string_it = str(arg1)
        snap_off = string_it.split('=')
        working_value = snap_off[1]
        return working_value[1:-1]

    def port(self,domain,port):
        port_result = []
        for i in port:
            s = socket.socket()
            s.settimeout(0.5)
            try:
                if s.connect_ex((domain, i)) == 0:
                    port_result.append(i)
                    s.close()
            except:
                pass
        return port_result

    def packetHandler(self,a):
        global hook_domains

        for pkt in a:  # read the packet
            if pkt.haslayer(DNSRR):  ## Read in a pcap and parse out the DNSRR Layer
                domain1 = pkt[DNSRR].rrname  # this is the response, it is assumed

                if domain1 != '':  # ignore empty and failures
                    domain = domain1[:-1]

                    record_log = {}

                    pkt_type = pkt[DNSRR].type  # identify the response record that requires parsing

                    # date/time
                    time_raw = pkt.time  # convert from unix to 8 digit date
                    pkt_date = (datetime.datetime.fromtimestamp(int(time_raw)).strftime('%Y%m%d %H:%M:%S'))

                    record_log['record_time'] = str(pkt_date)
                    record_log['dns_client_ip'] = pkt[IP].dst
                    record_log['dns_server_ip'] = pkt[IP].src

                    this_ip = []

                    if pkt_type == 2 or pkt_type == 5:  # this should work for type 5 and 2
                        x = pkt[DNSRR].answers
                        dns_strings = str(x)
                        fields = dns_strings.split('|')
                        for each in fields:
                            if 'type=NS' or 'type=A' in each:
                                subeach = str(each)
                                y = subeach.split(' ')  # split lines
                                for subsubeach in y:
                                    if 'rdata' in subsubeach:
                                        ipaddress = self.value_sniper(subsubeach)

                                        if ipaddress != None and self.ip_re.findall(ipaddress):
                                            this_ip.append(ipaddress)
                    elif pkt_type == 1 or pkt_type == 12 or pkt_type == 28:  # 32bit IP addresses
                        ipaddress = pkt[DNSRR].rdata
                        if self.ip_re.findall(ipaddress):
                            this_ip.append(ipaddress)
                    else:
                        pass

                    if this_ip and True not in map(lambda x: self.badDNS in x, this_ip):
                        if str(domain) not in self.passive_domain:
                            self.passive_domain.add(str(domain))
                            this_ip_result = ','.join([i for i in this_ip])
                            record_log['domain_ip'] = this_ip_result
                            record_log['domain'] = str(domain)
                            this_port = ','.join([str(i) for i in self.port(domain, [80, 443])])
                            if this_port:
                                record_log['port'] = this_port
                            else:
                                record_log['port'] = ''
                            print "[+]domain: " + str(domain),"[" + this_port + "]==>", this_ip_result, "[+]"
                            self.dnslogsQueueList.put(record_log)

    def run(self,interface='en0'):
        print "[+] Start Recording......"
        sniff(iface=interface, filter="udp and port 53", prn=self.packetHandler)

def run_sniff():

    parser = argparse.ArgumentParser(prog='PROG', description='Passive Dns collector with scapy.')
    parser.add_argument('-i', '--interface', help='specify the interface name default:en0 ')
    args = parser.parse_args()
    interface = ""
    hook_domains = []

    if args.interface:
        interface = args.interface

    stat = PassiveDNS()

    if len(interface) == 0:
        interface = stat.get_first_interface()
    try:
        gevent.joinall([gevent.spawn(stat.run, interface), gevent.spawn(stat.save_mysql)])
    except Exception,e:
        traceback.print_exc()
