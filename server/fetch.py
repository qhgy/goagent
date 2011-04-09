#!/usr/bin/env python
# coding=utf-8
# Based on GAppProxy by Du XiaoGang <dugang@188.com>
# Based on WallProxy 0.4.0 by hexieshe <www.ehust@gmail.com>

__version__ = '1.0'
__author__ =  'phus.lu@gmail.com'

import zlib, logging, time, re, struct
from google.appengine.ext import webapp
from google.appengine.ext import db
from google.appengine.ext.webapp.util import run_wsgi_app
from google.appengine.api import urlfetch
from google.appengine.runtime import apiproxy_errors

def _unquote_data(s):
    unquote_map = {'0':'\x10', '1':'=', '2':'&'}
    res = s.split('\x10')
    for i in xrange(1, len(res)):
        item = res[i]
        try:
            res[i] = unquote_map[item[0]] + item[1:]
        except KeyError:
            res[i] = '\x10' + item
    return ''.join(res)

def decode_data(qs, keep_blank_values=False, strict_parsing=False):
    pairs = qs.split('&')
    dic = {}
    for name_value in pairs:
        if not name_value and not strict_parsing:
            continue
        nv = name_value.split('=', 1)
        if len(nv) != 2:
            if strict_parsing:
                raise ValueError, "bad query field: %r" % (name_value,)
            if keep_blank_values:
                nv.append('')
            else:
                continue
        if len(nv[1]) or keep_blank_values:
            dic[_unquote_data(nv[0])] = _unquote_data(nv[1])
    return dic

def _quote_data(s):
    return str(s).replace('\x10', '\x100').replace('=','\x101').replace('&','\x102')

def encode_data(dic):
    res = []
    for k,v in dic.iteritems():
        res.append('%s=%s' % (_quote_data(k), _quote_data(v)))
    return '&'.join(res)

class MainHandler(webapp.RequestHandler):
    #FRS_Headers = ('', 'content-length', 'keep-alive', 'host', 'vary', 'via', 'x-forwarded-for',
    #              'proxy-authorization', 'proxy-connection', 'upgrade')
    FRP_Headers = ('', 'x-google-cache-control', 'via')
    Fetch_Max = 3
    Fetch_MaxSize = 512*1000
    Deadline = (15, 30)

    def sendResponse(self, status_code, headers, content='', method='', url=''):
        self.response.headers['Content-Type'] = 'application/octet-stream'
        contentType = headers.get('content-type', '').lower()

        headers = encode_data(headers)
        # Build send-data
        rdata = '%s%s%s' % (struct.pack('>3I', status_code, len(headers), len(content)), headers, content)
        if contentType.find('text')>=0 or contentType.find('application')>=0:
            data = zlib.compress(rdata)
            data = '1'+data if len(rdata)>len(data) else '0'+rdata
        else:
            data = '0' + rdata
        if status_code == 555:
            logging.warning('Response: "%s %s" %s' % (method, url, content))
        else:
            logging.debug('Response: "%s %s" %d %d/%d/%d' % (method, url, status_code, len(content), len(rdata), len(data)))
        return self.response.out.write(data)

    def sendNotify(self, status_code, content, method='', url='', fullContent=False):
        if not fullContent and status_code!=555:
            content = '<h2>Fetch Server Info</h2><hr noshade="noshade"><p>Code: %d</p>' \
                      '<p>Message: %s</p>' % (status_code, content)
        headers = {'server':'GoAgent/%s' % __version__, 'content-type':'text/html', 'content-length':len(content)}
        self.sendResponse(status_code, headers, content, method, url)

    def post(self):
        request = self.request.body
        request = decode_data(zlib.decompress(request))

        method = request.get('method', 'GET')
        if not hasattr(urlfetch, method):
            return self.sendNotify(555, 'Invalid Method', method)
        fetch_method = getattr(urlfetch, method)

        url = request.get('url', '')
        if not url.startswith('http'):
            return self.sendNotify(555, 'Unsupported Scheme', method, url)

        payload = request.get('payload', '')
        deadline = MainHandler.Deadline[1 if payload else 0]

        fetch_range = 'bytes=0-%d' % (MainHandler.Fetch_MaxSize - 1)
        rangeFetch = False
        headers = {}
        for line in request.get('headers', '').split('\n'):
            if ':' not in line:
                continue
            key, value = map(str.strip, line.split(':', 1))
            keyl = key.lower()
            #if keyl in MainHandler.FRS_Headers:
            #    continue
            if keyl == 'rangefetch':
                rangeFetch = True
                continue
            if keyl=='range' and not rangeFetch:
                m = re.search(r'(\d+)?-(\d+)?', value)
                if not m: continue
                m = [u and int(u) for u in m.groups()]
                if m[0] is None and m[1] is None:
                    continue
                if m[0] is None and m[1] > MainHandler.Fetch_MaxSize:
                    m[1] = 1023
                elif m[1] is None or m[1]-m[0]+1 > MainHandler.Fetch_MaxSize:
                    m[1] = MainHandler.Fetch_MaxSize - 1 + m[0]
                fetch_range = ('bytes=%s-%s' % (m[0], m[1])).replace('None', '')
            headers[key] = value
        headers['Connection'] = 'close'

        for i in range(MainHandler.Fetch_Max):
            try:
                response = urlfetch.fetch(url, payload, fetch_method, headers, False, False, deadline)
                #if method=='GET' and len(response.content)>0x1000000:
                #    raise urlfetch.ResponseTooLargeError(None)
                break
            except apiproxy_errors.OverQuotaError, e:
                time.sleep(4)
            except urlfetch.InvalidURLError, e:
                return self.sendNotify(555, 'Invalid URL: %s' % e, method, url)
            except urlfetch.ResponseTooLargeError, e:
                if method == 'GET':
                    deadline = MainHandler.Deadline[1]
                    if not rangeFetch:
                        headers['Range'] = fetch_range
                else:
                    return self.sendNotify(555, 'Response Too Large: %s' % e, method, url)
            except Exception, e:
                if i==0 and method=='GET':
                    deadline = MainHandler.Deadline[1]
                    if not rangeFetch:
                        headers['Range'] = fetch_range
        else:
            return self.sendNotify(555, 'Urlfetch error: %s' % e, method, url)

        for k in MainHandler.FRP_Headers:
            if k in response.headers:
                del response.headers[k]
        if 'set-cookie' in response.headers:
            scs = response.headers['set-cookie'].split(', ')
            cookies = []
            i = -1
            for sc in scs:
                if re.match(r'[^ =]+ ', sc):
                    try:
                        cookies[i] += ', '+sc
                    except:
                        pass
                else:
                    cookies.append(sc)
                    i += 1
            response.headers['set-cookie'] = '\r\nSet-Cookie: '.join(cookies)
        response.headers['connection'] = 'close'
        return self.sendResponse(response.status_code, response.headers, response.content, method, url)

    def get(self):
        self.response.headers['Content-Type'] = 'text/html; charset=utf-8'
        self.response.out.write( \
'''
<html>
    <head>
        <meta http-equiv="Content-Type" content="text/html; charset=utf-8" />
        <title>GoAgent已经在工作了</title>
    </head>
    <body>
        <table width="800" border="0" align="center">
            <tr><td align="center"><hr></td></tr>
            <tr><td align="center">
                <b><h1>GoAgent/%s 已经在工作了</h1></b>
            </td></tr>
            <tr><td align="center"><hr></td></tr>

            <tr><td align="center">
                GoAgent是一个开源的HTTP Proxy软件,使用Python编写,运行于Google App Engine平台上.
            </td></tr>
            <tr><td align="center"><hr></td></tr>

            <tr><td align="center">
                更多相关介绍,请参考<a href="https://github.com/phus/goagent">GoAgent项目主页</a>.
            </td></tr>
            <tr><td align="center"><hr></td></tr>

            <tr><td align="center">
                <img src="http://code.google.com/appengine/images/appengine-silver-120x30.gif" alt="Powered by Google App Engine" />
            </td></tr>
            <tr><td align="center"><hr></td></tr>
        </table>
    </body>
</html>
''' % __version__)

def main():
    application = webapp.WSGIApplication([(r'/.*', MainHandler)], debug=True)
    run_wsgi_app(application)

if __name__ == "__main__":
    main()