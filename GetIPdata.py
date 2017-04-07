#!/usr/bin/env python -u
# -*- coding: utf-8 -*-
# encoding=utf8
import ConfigParser
import sys, os, re
import argparse
import datetime
import inspect
import logging

reload(sys)
sys.setdefaultencoding('utf8')

defaultConfig="config.ini"
Config = ConfigParser.ConfigParser()
Config.read(defaultConfig)

parser = argparse.ArgumentParser(
    description='Process some file.',
    epilog='comments > /dev/null'
)
parser.add_argument('--ListSites', "-l",  action='store_true', help='Show sources')
parser.add_argument('--verbose', "-v",  action='store_true', help='Sure?')
#parser.add_argument('--User', "-u", type=str, help='A user')

args=parser.parse_args()

browserAgent={'User-Agent': 'None',
                    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                    'Accept-Charset': 'utf-8;q=0.7,*;q=0.3',
                    'Accept-Encoding': 'none',
                    'Accept-Language': 'en-US,en;q=0.8',
                    'Connection': 'keep-alive'}

resultsFile=Config.get('LOG', 'Path')+Config.get('LOG', 'JsonResult')
proxy=""
VERBOSE = False

#---------------------------------------------------
def whoami():
    return inspect.stack()[1][3]
#---------------------------------------------------
def configlogging():
    # logging.basicConfig(filename=Config.get('LOG','FileLog'),level=Config.get('LOG','Level'),format=Config.get('LOG','Format'),datefmt=Config.get('LOG','DateFMT'))
    logging.basicConfig(filename=(Config.get('LOG', 'Path') + Config.get('LOG', 'FileLog')),
                        level=Config.get('LOG', 'Level'),
                        format='%(asctime)s:%(levelname)s:%(message)s', datefmt='%m/%d/%Y %I:%M:%S %p')
# ---------------------------------------------------
def ListSources(sources):
    for i in sources:
        print i
# ---------------------------------------------------
# ---------------------------------------------------
# ---------------------------------------------------
# ---------------------------------------------------
# ---------------------------------------------------
logging.info("[BEGIN]")
dt=datetime.datetime.now()

if not os.path.exists(Config.get('LOG', 'Path')) :
    print ('Dir {0} not found, created').format(Config.get('LOG', 'Path'))
    os.makedirs(Config.get('LOG', 'Path'))
    configlogging()
    logging.warning('Dir {0} not found, created').format(Config.get('LOG', 'Path'))
else:
    configlogging()

if not os.path.exists(Config.get('DATA', 'Path')) :
    os.makedirs(Config.get('DATA', 'Path'))
    print ('Dir {0} not found, created').format(Config.get('DATA', 'Path'))
    logging.warning('Dir {0} not found, created').format(Config.get('DATA', 'Path'))

if args.verbose:
    VERBOSE = True

if args.ListSites:
    ListSources(Config.get('SITES'))
