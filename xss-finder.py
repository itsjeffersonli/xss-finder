!/usr/bin/env python
import mechanize
import sys
import httplib
import argparse
import logging
from urlparse import urlparse0

br = mechanize.Browser() 
br.addheaders = [
    ('User-agent',
     'Mouguoudbsajdhbsa.8.1.11)Gecko/20071127 Firefox/2.0.0.11')
]
br.set_handle_robots(False)
br.set_handle_refresh(False)

f = open('payload', "r")
payloads = list(f)
f.close()

#payloads = ['dompayload']
blacklist = ['.png', '.jpg', '.jpeg', '.mp3', '.mp4', '.avi', '.gif', '.svg',
             '.pdf']
xssLinks = []           


class color:
    BLUE = '\033[94m'
    RED = '\033[91m'
    GREEN = '\033[92m'
    BLUE = '\033[93m'
    MAGENTA = '\033[35m'
    BOLD = '\033[1m'
    END = '\033[0m'

    @staticmethod
    def log(lvl, col, msg):
        logger.log(lvl, col + msg + color.END)


print (color.BOLD + color.BOLD + """
Example(1) :  Python2 xssfinder.py -u https://www.google.com -e -v -c cookie=hello
Example(2) :  Python2 xssfinder.py -u http://www.google.com -e -v -c cookie=hello
Help       :  Python2 xssfinder.py -h


""" + color.END)

logger = logging.getLogger(__name__)
lh = logging.StreamHandler()
logger.addHandler(lh)
formatter = logging.Formatter('[%(asctime)s] %(message)s', datefmt='%H:%M:%S')
lh.setFormatter(formatter)

parser = argparse.ArgumentParser()
parser.add_argument('-u', action='store', dest='url',
                    help='The URL to analyze')
parser.add_argument('-e', action='store_true', dest='compOn',
                    help='Enable comprehensive scan')
parser.add_argument('-v', action='store_true', dest='verbose',
                    help='Enable verbose logging')
parser.add_argument('-c', action='store', dest='cookies',
                    help='Space separated list of cookies',
                    nargs='+', default=[])
results = parser.parse_args()

logger.setLevel(logging.DEBUG if results.verbose else logging.INFO)


def testPayload(payload, p, link):
    br.form[(p.name)] = payload
    br.submit()
    # if payload is found in response, we have XSS
    if payload in br.response().read():
        color.log(logging.DEBUG, color.BOLD + color.RED, 'Found XSS Reflection')
        report = 'Link: %s, Payload: %s, Element: %s' % (str(link),
                                                         payload, (p.name))
        color.log(logging.INFO, color.BOLD + color.GREEN, report)
        xssLinks.append(report)
    br.back()


def initializeAndFind():

    if not results.url:    # if the url has been passed or not
        color.log(logging.INFO, color.GREEN, 'Url not provided correctly')
        return []

    firstDomains = []    # list of domains
    firstDomains.append(results.url)
    allURLS = []
    allURLS.append(results.url)    # just one url at the moment
    largeNumberOfUrls = []    # in case one wants to do comprehensive search
    largeNumberOfUrls.append(results.url)


    color.log(logging.INFO, color.GREEN, 'Performing short scan')
    for url in allURLS:
        smallurl = str(url)

        try:
            test = httplib.HTTPSConnection(smallurl)
            test.request("GET", "/")
            response = test.getresponse()
            if (response.status == 200) | (response.status == 302):
                url = str(url)
            elif response.status == 301:
                loc = response.getheader('Location')
                url = loc.scheme + '://' + loc.netloc
            else:
                url = str(url)
        except:
            url = str(url)
        try:
            br.open(url)
            for cookie in results.cookies:
                color.log(logging.INFO, color.BLUE,
                          'Adding cookie: %s' % cookie)
                br.set_cookie(cookie)
            br.open(url)
            color.log(logging.INFO, color.GREEN,
                      'Crawling links in ' + str(url))
            for link in br.links():        # finding the links of the website
                if smallurl in str(link.absolute_url):
                    firstDomains.append(str(link.absolute_url))
            firstDomains = list(set(firstDomains))
        except:
            pass
        color.log(logging.INFO, color.GREEN,
                  'Crawled links ' + str(len(firstDomains)))
        if results.compOn:
            color.log(logging.INFO, color.GREEN,
                      'Performing comprehensive scan')
            for link in firstDomains:
                try:
                    br.open(link)
                   
										for newlink in br.links():
                        if smallurl in str(newlink.absolute_url):
                            largeNumberOfUrls.append(newlink.absolute_url)
                except:
                    pass
            firstDomains = list(set(firstDomains + largeNumberOfUrls))
            color.log(logging.INFO, color.GREEN,
                      'Total Number of links to test have become: ' +
                      str(len(firstDomains)))  # all links have been found
    return firstDomains


def findxss(firstDomains):
    # starting finding XSS
    color.log(logging.INFO, color.GREEN, 'Performing XSS')
    if firstDomains:    # if there is atleast one link
        for link in firstDomains:
            blacklisted = False
            y = str(link)
            color.log(logging.DEBUG, color.GREEN, str(link))
            for ext in blacklist:
                if ext in y:
                    color.log(logging.DEBUG, color.RED,
                              '\tNot a good url to test')
                    blacklisted = True
                    break
            if not blacklisted:
                try:
                    br.open(str(link))    # open the link
                    if br.forms():        # if a form exists, submit it
                        params = list(br.forms())[0]    # our form
                        br.select_form(nr=0)    # submit the first form
                        for p in params.controls:
                            par = str(p)
                            # submit only those forms which require text
                            if 'TextControl' in par:
                                color.log(logging.DEBUG, color.BLUE,
                                          '\tParam: ' + (p.name))
                                for item in payloads:
                                    testPayload(item, p, link)
                except:
                    pass
        color.log(logging.DEBUG, color.GREEN + color.BOLD,
                  'Vulnerable list [If empty, none!] ')
        for link in xssLinks:        # print all xss findings
            color.log(logging.DEBUG, color.GREEN, '\t' + link)
    else:
        color.log(logging.INFO, color.RED + color.BOLD,
                  '\tNo link found, exiting')
    exit(0)

# calling the function
firstDomains = initializeAndFind()
findxss(firstDomains)