#!/usr/bin/env python -u
# -*- coding: utf-8 -*-
# encoding=utf8
import ConfigParser
import sys, os, re
import argparse
import datetime
import inspect
import logging
import urllib2
import progressbar as pb
import json
import threading
import Queue
import socket
from bs4 import BeautifulSoup

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
parser.add_argument('--time', "-t",  type=str, help='Only for pastebin, you can choose current, 7, 30, 365')
parser.add_argument('--verbose', "-v",  action='store_true', help='Sure?')
parser.add_argument('--Site', "-s",  type=str, help='Sure?')
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
VERBOSE=False

#---------------------------------------------------
def whoami():
    return inspect.stack()[1][3]
#---------------------------------------------------
def configlogging():
    if VERBOSE:
        myself = whoami()
        print ("[{0:10}] configuring").format(myself)
    # logging.basicConfig(filename=Config.get('LOG','FileLog'),level=Config.get('LOG','Level'),format=Config.get('LOG','Format'),datefmt=Config.get('LOG','DateFMT'))
    logging.basicConfig(filename=(Config.get('LOG', 'Path') + Config.get('LOG', 'FileLog')),
                        level=Config.get('LOG', 'Level'),
                        format='%(asctime)s:%(levelname)s:%(message)s', datefmt='%m/%d/%Y %I:%M:%S %p')
# ---------------------------------------------------
def ListSources(sources):
    print "\n"
    for m,n in sources.items('SITES'):
        print ("{0:02}-\t{1}").format(int(m),n)
    print "\n"
# ---------------------------------------------------
def malwaredomainlist(url, page, option):
    case={1:Config.get(Config.get('SITES', args.Site), 'fileip'),
            2:Config.get(Config.get('SITES', args.Site), 'filehost')}
    if VERBOSE:
        myself = whoami()
        print ("[{0:10}] begin").format(myself)
    yamlFile = open(Config.get('DATA', 'Path') + case[option], 'w')
    widgets = ['Getting data from [{0}]: '.format(url), pb.Percentage(), ' ',
               pb.Bar(marker=pb.RotatingMarker()), ' ', pb.ETA()]
    timer = pb.ProgressBar(widgets=widgets, maxval=1000000).start()
    i=0
    for line in page.readlines():
        i+=1
        line = re.sub('\\r|\\n', '', line)
        if option == 2:
            if re.search('^\d+\.', line):
                line = re.sub('\d{1,3}\.\d{1,3}\.\d{1,4}\.\d{1,3}\s+', '', line)
                line.replace(r'^M','')
            else:
                line =''

        timer.update(i)
        if line:
            yamlFile.write("\"" + line + "\": \"YES\"" + "\n")
    yamlFile.close
    timer.finish()
    if i:
        print ("{0} problems find".format(i))
        print ("File {0} created !!!").format(Config.get('DATA', 'Path')+case[option])
    else:
        logging.error('NO DATA FOUND. try wget {0}'.format(url))
        os.remove(Config.get('DATA', 'Path') + case[option])
    if VERBOSE:
        print ("[{0:10}] end").format(myself)
# ---------------------------------------------------
def IPSIMPLEproject(url, page, option):
    if VERBOSE:
        myself = whoami()
        print ("[{0:10}] begin").format(myself)
    yamlFile = open(Config.get('DATA', 'Path') + Config.get(Config.get('SITES', args.Site), 'fileip'), 'w')
    widgets = ['Getting data from [{0}]: '.format(url), pb.Percentage(), ' ',
               pb.Bar(marker=pb.RotatingMarker()), ' ', pb.ETA()]
    timer = pb.ProgressBar(widgets=widgets, maxval=1000000).start()
    i=0
    if option == '4' :
        for line in ( page.split('\n') ):
            if re.search('^\d+\.', line):
                i += 1
                timer.update(i)
                yamlFile.write("\"" + line + "\": \"YES\"" + "\n")
    else:
        for line in page.readlines():
            line = re.sub('\\r|\\n', '', line)
            if line.startswith('ExitAddress'):
                i+=1
                ip = line.split()[1]
                timer.update(i)
                yamlFile.write("\"" + ip + "\": \"YES\"" + "\n")
            elif option == '3':
                i += 1
                timer.update(i)
                yamlFile.write("\"" + line + "\": \"YES\"" + "\n")
    timer.finish()
    yamlFile.close
    if i:
        print ("{0} IPs malicious find".format(i))
        print ("File {0} created !!!").format(Config.get('DATA', 'Path')+Config.get(Config.get('SITES', args.Site), 'fileip'))
    else:
        logging.error('NO DATA FOUND. try wget {0}'.format(url))
        os.remove(Config.get('DATA', 'Path') + Config.get(Config.get('SITES', args.Site), 'fileip'))
    if VERBOSE:
        print ("[{0:10}] end").format(myself)
# ---------------------------------------------------
def getLinks(site,url,browserAgent,dt):
    myself=whoami()
    print ("[{0:10}] opennig mode:[{1}]").format(myself,site)
    logging.info(("[{0:10}]:opennig mode:[{1}]").format(myself,site))
    data = json.dumps({site: {'URLS': []}})
    try:
        req = urllib2.Request(url, headers=browserAgent)
        html = urllib2.urlopen(req).read()
    except urllib2.HTTPError as e:
        print ("[{0:10}] Fail:[{1}]".format(myself,e))
        logging.warning("[{0:10}]:Fail:[{1}]".format(myself,e))
        return None
    try:
        bsObj = BeautifulSoup(html, "lxml")
        letters = bsObj.find_all("td")
    except urllib2.HTTPError as e:
        print "[{0:10}] Fail:[{1}]".format(myself,e)
        logging.warning("[{0:10}]:Fail:[{1}]".format(myself,e))
        return None
    cont=0
    urlpages=[]
    for element in letters:
        try:
            if not re.search('\/u\/',element.a["href"]):
                urlpages.append(element)
        except: None
    print ("[{0:10}] {1} links managed").format(myself,len(urlpages))
    prefix = Config.get('PASTEBIN', 'prefix')
    link = forkLink( site, prefix, urlpages, data, dt)
    logging.info(("[{0:10}]:Links OK").format(myself))
    return json.dumps(link)
# ---------------------------------------------------
def forkLink (site, prefix, urlpages, data, dt):
    myself = whoami()
    threads = list()
    logging.info(("[{0:10}]:Starting Threads data for {1}").format(myself, site))
    queueLock = threading.Lock()
    workQueue = Queue.Queue(len(urlpages))
    workOut = Queue.Queue(2000)
    threads = []
    threadID = 1
    for i in range(len(urlpages)):
        logging.info(("[{0:10}]:Thread data for {1}").format(myself, i))
        thread = threading.Thread(target=workerThreadPage, args=(threadID, urlpages[i], site, prefix, data, workOut, dt))
        thread.daemon
        thread.start()
        threads.append(thread)
        threadID += 1

    logging.info(("[{0:10}]:All threads started").format(myself))

    for link in urlpages:
        workQueue.put(link)
    logging.info("[{0:10}]:current data loaded".format(myself))


    for t in threads:
        t.join()

    logging.info(("[{0:10}]:Exiting Main Thread").format(myself))
    cont=0
    link=[]
    while not workOut.empty():
        linkE = workOut.get()
        for i in linkE :
            link.append(i)
    data = json.dumps({site:{'URLS':link}})
    return data
#---------------------------------------------------
def workerThreadPage (threadID, element, site, prefix, data, workOut, dt):
    myself=whoami()
    myself+="-threadID-"+str(threadID)
    pagename=element.a["href"].lstrip('/')
    print ("[{0:10}] Verifing {1}").format(myself, pagename)
    logging.info("[{0:10}]:Verifing {1}".format(myself, pagename))
    scoring=0
    link=[]
    logging.info(("[{0:10}]:Flag False {1}").format(myself, pagename))
    scoring = getPage(threadID, pagename,
                      "http://" + prefix + element.a["href"],
                      Config.get('DATA', 'Path') + pagename,
                      browserAgent)
    link.append({'page': pagename, 'url': prefix + element.a["href"], 'message': element.text, 'scoring': scoring,
         'datetime': str(dt)})
    minimumScore = Config.get('DATA', 'MinimumScore')

    logging.info(("[{0:10}]:Links OK").format(myself))

    workOut.put(link)
# ---------------------------------------------------
def getPage (threadID, name, url, fileRaw, browserAgent):
    myself = whoami()
    myself += "-threadID-" + str(threadID)
    print ("[{0:10}] [open] data from :{1}").format(myself,url)
    logging.info("[{0:10}]:[open] data from :{1}".format(myself,url))
    minimumScore = Config.get('DATA', 'MinimumScore')
    logging.info("[{0:10}]:\tMinimum score needed :{1}".format( myself, minimumScore))
    timeout = float(Config.get('CONST', 'TimeOUT'))
    socket.setdefaulttimeout(timeout)
    req = urllib2.Request(url, headers=browserAgent)
    html = urllib2.urlopen(req).read()
    bsObj = BeautifulSoup(html,"lxml")
    scoring=0
    checks={}
    fd= open (fileRaw,'w')

    for line in str(bsObj).splitlines():
        fd.write(line+"\n")
        if VERBOSE:
            print line
        else:
            print "#",
        line.replace(" ", "")
        line.replace("`", "")
        line.replace("(\r){0,1}\n", "")
        keywords=Config.items('CODEWORDS')
        for kw in keywords:
            print ".",
            try:
                if re.search(kw[1],line.upper()):
                    print ("[{}]").format(kw[1])
                    sys.stdout.flush()
                    try :
                        checks[kw[0]]+=1
                    except:
                        checks.update({kw[0]:1})
                    scoring = scoring +int(kw[0])
            except: None
    print ("\nFinal Score: {}").format(scoring)
    sys.stdout.flush()
    logging.info("[{0:10}]:\t[score]{1}:{2}".format(myself,name,scoring))
    fd.close()
    logging.info("[{0:10}]:[close] {1} ".format(myself,url))
    if int(scoring) <= int(minimumScore):
        logging.warning("[{0:10}]:scoring lower [{1}] than minimumScore {2}".format(myself, scoring, minimumScore))
        os.remove(fileRaw)
        logging.warning("[{0:10}]:[{1}] deleted.".format(myself,name))
    print ("[{0:10}] page OK").format(myself)
    logging.info(("[{0:10}]:page OK").format(myself))
    return {'value': scoring, 'checks': checks}
# ---------------------------------------------------
# ---------------------------------------------------
def main():
    logging.info("[BEGIN]")
    dt=datetime.datetime.now()
    if not os.path.exists(Config.get('LOG', 'Path')) :
        print ('Dir {0} not found, created').format(Config.get('LOG', 'Path'))
        os.makedirs(Config.get('LOG', 'Path'))
        configlogging()
        logging.warning('Dir {0} not found, created'.format(Config.get('LOG', 'Path')))
    else:
        configlogging()

    if not os.path.exists(Config.get('DATA', 'Path')) :
        os.makedirs(Config.get('DATA', 'Path'))
        print ('Dir {0} not found, created').format(Config.get('DATA', 'Path'))
        logging.warning('Dir {0} not found, created'.format(Config.get('DATA', 'Path')))

    if args.verbose:
        VERBOSE = True
    if args.Site:
        if Config.has_option('SITES',args.Site):
            if args.Site == '1':
                pages = getLinks('PASTEBIN', Config.get(Config.get('SITES',args.Site),'pastebinTrend'), browserAgent, dt)
                fd = open(resultsFile, "w")
                fd.write(pages)
                fd.close
            elif args.Site == '2':
                response = urllib2.urlopen(Config.get(Config.get('SITES',args.Site),'ip'))
                if response.getcode() == 200:
                    malwaredomainlist(Config.get(Config.get('SITES',args.Site),'ip'), response, 1)
                else:
                    logging.error('error page {0} '.format(response.getcode()))

                response = urllib2.urlopen(Config.get(Config.get('SITES', args.Site), 'host'))
                if response.getcode() == 200:
                    malwaredomainlist(Config.get(Config.get('SITES', args.Site), 'host'), response, 2)
                else:
                    logging.error('error page {0} '.format(response.getcode()))

            elif args.Site == '5' or args.Site == '3':
                response = urllib2.urlopen(Config.get(Config.get('SITES',args.Site),'ip'))
                if response.getcode() == 200:
                    IPSIMPLEproject(Config.get(Config.get('SITES',args.Site),'ip'), response, args.Site)
                else:
                    logging.error('error page {0} '.format(response.getcode()))
            elif args.Site == '4':
                print Config.get(Config.get('SITES', args.Site), 'ip')
                req = urllib2.Request(Config.get(Config.get('SITES', args.Site), 'ip'), headers=browserAgent)
                response = urllib2.urlopen(req).read()
                IPSIMPLEproject(Config.get(Config.get('SITES', args.Site), 'ip'), response, args.Site)
            else:
                print "eo"



        else:
            print ("\nOption {0} output of range.\nSelect other:").format(args.Site)
            ListSources(Config)
    elif args.ListSites:
        ListSources(Config)
# ---------------------------------------------------
# ---------------------------------------------------
if __name__ == '__main__':
	main()
