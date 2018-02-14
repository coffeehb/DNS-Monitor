#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Time    : 2018/2/13 下午10:17
# @Author  : Komi
# @File    : run.py
# @Ver:    : 0.1

import threading

from libs.sniff import run_sniff
from web import run_web

if __name__ == '__main__':
    threading.Thread(target=run_sniff).start()
    threading.Thread(target=run_web).start()

    print "[*] Run Server......"

