#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Time    : 2018/2/13 下午12:52
# @Author  : Komi
# @File    : core.py
# @Ver:    : 0.1

import os
import MySQLdb as mysql
import ConfigParser


class LogsHelper:

    def __init__(self):
        self.passive_domain = []
        self.conf = self.load_all_config()

        self.init_config()
        self.init_proxyserver()

    def init_proxyserver(self):
        try:

            self.listen_ip = self.conf['proxyserver']['listen_ip']
            self.listen_port = self.conf['proxyserver']['listen_port']
            self.login_name = self.conf['proxyserver']['username']
            self.login_pass = self.conf['proxyserver']['password']
        except Exception as e:
            print e

    def init_config(self):
        try:
            db_ip = self.conf['database']['ip']
            db_port = self.conf['database']['port']
            db_username = self.conf['database']['username']
            db_password = self.conf['database']['password']
            dbname = self.conf['database']['dbname']

            conn = mysql.connect(user=db_username, passwd=db_password, host=db_ip, db=dbname, port=int(db_port))
            self.cur = conn.cursor()

        except Exception as e:
            print e

    def get_all_dnslogs(self):
        try:
            sql = "select * from dnslogs order by record_time DESC"
            self.cur.execute(sql)
            for i in self.cur.fetchall():
                log = {}
                log['id'] = i[0]
                log['domain'] = i[1]
                log['ip'] = i[2]
                log['port'] = i[3]
                log['time'] = i[6]
                self.passive_domain.append(log)
        except Exception, e:
            print e
            print '\033[91m' + '\033[1m' + '[+].... Pull Domain From Database Error ....[+]' + '\033[0m'
        finally:
            return self.passive_domain

    def load_all_config(self):
        config_ini = 'config.ini'

        fn = os.path.abspath(os.path.join(os.path.dirname(__file__), config_ini))
        parser = ConfigParser.ConfigParser()
        parser.read(fn)

        config = {}
        for n in parser.sections():
            d = {}
            for k, v in parser.items(n):
                d[k] = v
            config[n] = d

        return config
