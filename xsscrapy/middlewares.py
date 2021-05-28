from scrapy.exceptions import IgnoreRequest
from urlparse import unquote, urlparse
from pybloom import BloomFilter
import random
import re
from settings import bloomfilterSize
import requests
import urllib

# Filter out duplicate requests with Bloom filters since they're much easier on memory
#URLS_FORMS_HEADERS = BloomFilter(3000000, 0.00001)
URLS_SEEN = BloomFilter(bloomfilterSize, .0001)
FORMS_SEEN = BloomFilter(bloomfilterSize, .0001)
HEADERS_SEEN = BloomFilter(bloomfilterSize, .0001)
USER_AGENT_LIST = ['Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/34.0.1847.131 Safari/537.36',
                   'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_9_2) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/34.0.1847.131 Safari/537.36',
                   'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_9_2) AppleWebKit/537.75.14 (KHTML, like Gecko) Version/7.0.3 Safari/537.75.14',
                   'Mozilla/5.0 (Windows NT 6.1; WOW64; rv:29.0) Gecko/20100101 Firefox/29.0',
                   'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/34.0.1847.137 Safari/537.36',
                   'Mozilla/5.0 (Windows NT 6.1; WOW64; rv:28.0) Gecko/20100101 Firefox/28.0']

class RandomUserAgentMiddleware(object):
    ''' Use a random user-agent for each request '''
    def process_request(self, request, spider):
        ua = random.choice(USER_AGENT_LIST)
        if 'payload' in request.meta:
            payload = request.meta['payload']
            if 'User-Agent' in request.headers:
                if payload == request.headers['User-Agent']:
                    return

        request.headers.setdefault('User-Agent', ua)
        request.meta['UA'] = ua

class InjectedDupeFilter(object):
    ''' Filter duplicate payloaded URLs, headers, and forms since all of those have dont_filter = True '''

    def process_request(self, request, spider):

        meta = request.meta
        if 'xss_place' not in meta:
            return
        delim = meta['delim']
        payload = meta['payload']
        orig_url= meta['orig_url']

        # Injected URL dupe handling
        if meta['xss_place'] == 'url':
            url = request.url
            #replace the delim characters with nothing so we only test the URL
            #with the payload
            no_delim_url = url.replace(delim, '')
            if no_delim_url in URLS_SEEN:
                raise IgnoreRequest
            spider.log('Sending payloaded URL: %s' % url)
            URLS_SEEN.add(url)
            
            # MY METHOD CALLS
            self.writeToFile(orig_url)
            self.checkForCodeInjection(url, payload)
            
            return

        # Injected form dupe handling
        elif meta['xss_place'] == 'form':
            u = meta['POST_to']
            p = meta['xss_param']
            u_p = (u, p)
            if u_p in FORMS_SEEN:
                raise IgnoreRequest
            spider.log('Sending payloaded form param %s to: %s' % (p, u))
            FORMS_SEEN.add(u_p)
            return

        # Injected header dupe handling
        elif meta['xss_place'] == 'header':
            u = request.url
            h = meta['xss_param']
            # URL, changed header, payload
            u_h = (u, h)
            if u_h in HEADERS_SEEN:
                raise IgnoreRequest
            spider.log('Sending payloaded %s header' % h)
            HEADERS_SEEN.add(u_h)
            return
        
    ################## MY CODE STARTS HERE ####################
    
    def checkForCodeInjection(self, url, xssPayload):
        ciPayload="bountyKing{{9*9}}"
        payloadExecuted="bountyKing81"

        url = self.prepareUrl(url, xssPayload, ciPayload)
        
        spider.log('Sending Code Injection URL: %s' % url)
        
        response = requests.get(url)
        
        if payloadExecuted in str(response.content):
           spider.log('BOOOOOOOOOOOOOM! Code Injection Found! URL: %s' % url)
           
           with open("codeInjection-"+self.getHost(url)+".txt", "a") as output:
            output.write("URL: " + url +"\n")
            output.write("Payload: " + ciPayload +"\n")
            output.write(str(response.content)+"\n")
            output.write(url+"\n\n\n")
    
    # Ersetze in einer Url den Payload von XSScrapy (oldPayload) mit einen eigenen (newPayload)
    def prepareUrl(self, url, oldPayload, newPayload):
        oldPayload = oldPayload.replace("'\"(){}<x>", "'%22()%7B%7D%3Cx%3E")
        #print oldPayload
        #print newPayload
        #print url
        url = url.replace(oldPayload, newPayload)
        return url
    
    # Gebe den Urls von einer Url zurueck, z.B. aus https://example.com/1/2/i.html wird example.com
    def getHost(self, url):
        host = url.replace("https://", "")
        host = host.replace("http://", "")
        host = host.split("/")[0]
        return host
    
    def writeToFile(self, url):
        with open("urls/urls-"+self.getHost(url)+".txt", "a") as output:
            output.write(url+"\n")
