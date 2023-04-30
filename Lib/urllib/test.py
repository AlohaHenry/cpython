# from urllib.request import *
import socket
import bisect
import sys

import base64
import ssl
import email
import hashlib
import http.client
import io
import os
import re
import string
import time
import tempfile
import contextlib
import warnings

class Request:

    def __init__(self, url, data=None, headers={},
                 origin_req_host=None, unverifiable=False,
                 method=None):
        self.full_url = url
        self.headers = {}
        self.unredirected_hdrs = {}
        self._data = None
        self.data = data
        self._tunnel_host = None
        for key, value in headers.items():
            self.add_header(key, value)
        if origin_req_host is None:
            origin_req_host = request_host(self)
        self.origin_req_host = origin_req_host
        self.unverifiable = unverifiable
        if method:
            self.method = method

    @property
    def full_url(self):
        if self.fragment:
            return '{}#{}'.format(self._full_url, self.fragment)
        return self._full_url

    @full_url.setter
    def full_url(self, url):
        # unwrap('<URL:type://host/path>') --> 'type://host/path'
        self._full_url = unwrap(url)
        self._full_url, self.fragment = _splittag(self._full_url)
        self._parse()

    @full_url.deleter
    def full_url(self):
        self._full_url = None
        self.fragment = None
        self.selector = ''

    @property
    def data(self):
        return self._data

    @data.setter
    def data(self, data):
        if data != self._data:
            self._data = data
            # issue 16464
            # if we change data we need to remove content-length header
            # (cause it's most probably calculated for previous value)
            if self.has_header("Content-length"):
                self.remove_header("Content-length")

    @data.deleter
    def data(self):
        self.data = None

    def _parse(self):
        self.type, rest = _splittype(self._full_url)
        if self.type is None:
            raise ValueError("unknown url type: %r" % self.full_url)
        self.host, self.selector = _splithost(rest)
        if self.host:
            self.host = unquote(self.host)

    def get_method(self):
        """Return a string indicating the HTTP request method."""
        default_method = "POST" if self.data is not None else "GET"
        return getattr(self, 'method', default_method)

    def get_full_url(self):
        return self.full_url

    def set_proxy(self, host, type):
        if self.type == 'https' and not self._tunnel_host:
            self._tunnel_host = self.host
        else:
            self.type= type
            self.selector = self.full_url
        self.host = host

    def has_proxy(self):
        return self.selector == self.full_url

    def add_header(self, key, val):
        # useful for something like authentication
        self.headers[key.capitalize()] = val

    def add_unredirected_header(self, key, val):
        # will not be added to a redirected request
        self.unredirected_hdrs[key.capitalize()] = val

    def has_header(self, header_name):
        return (header_name in self.headers or
                header_name in self.unredirected_hdrs)

    def get_header(self, header_name, default=None):
        return self.headers.get(
            header_name,
            self.unredirected_hdrs.get(header_name, default))

    def remove_header(self, header_name):
        self.headers.pop(header_name, None)
        self.unredirected_hdrs.pop(header_name, None)

    def header_items(self):
        hdrs = {**self.unredirected_hdrs, **self.headers}
        return list(hdrs.items())


class OpenerDirector:
    def __init__(self):
        client_version = "Python-urllib/version"
        self.addheaders = [('User-agent', client_version)]
        # self.handlers is retained only for backward compatibility
        self.handlers = []
        # manage the individual handlers
        self.handle_open = {}
        self.handle_error = {}
        self.process_response = {}
        self.process_request = {}

    def add_handler(self, handler):
        if not hasattr(handler, "add_parent"):
            raise TypeError("expected BaseHandler instance, got %r" %
                            type(handler))

        added = False
        for meth in dir(handler):
            if meth in ["redirect_request", "do_open", "proxy_open"]:
                # oops, coincidental match
                continue

            i = meth.find("_")
            protocol = meth[:i]
            condition = meth[i+1:]

            if condition.startswith("error"):
                j = condition.find("_") + i + 1
                kind = meth[j+1:]
                try:
                    kind = int(kind)
                except ValueError:
                    pass
                lookup = self.handle_error.get(protocol, {})
                self.handle_error[protocol] = lookup
            elif condition == "open":
                kind = protocol
                lookup = self.handle_open
            elif condition == "response":
                kind = protocol
                lookup = self.process_response
            elif condition == "request":
                kind = protocol
                lookup = self.process_request
            else:
                continue

            handlers = lookup.setdefault(kind, [])
            if handlers:
                bisect.insort(handlers, handler)
            else:
                handlers.append(handler)
            added = True

        if added:
            bisect.insort(self.handlers, handler)
            handler.add_parent(self)

    def _call_chain(self, chain, kind, meth_name, *args):
        # Handlers raise an exception if no one else should try to handle
        # the request, or return None if they can't but another handler
        # could.  Otherwise, they return the response.
        handlers = chain.get(kind, ())
        for handler in handlers:
            func = getattr(handler, meth_name)
            result = func(*args)
            if result is not None:
                return result

    def open(self, fullurl, data=None, timeout=socket._GLOBAL_DEFAULT_TIMEOUT):
        # accept a URL or a Request object
        if isinstance(fullurl, str):
            req = Request(fullurl, data)
        else:
            req = fullurl
            if data is not None:
                req.data = data

        req.timeout = timeout
        protocol = req.type

        # pre-process request
        meth_name = protocol+"_request"
        for processor in self.process_request.get(protocol, []):
            meth = getattr(processor, meth_name)
            req = meth(req)

        sys.audit('urllib.Request', req.full_url, req.data, req.headers, req.get_method())
        response = self._open(req, data)

        # post-process response
        meth_name = protocol+"_response"
        for processor in self.process_response.get(protocol, []):
            meth = getattr(processor, meth_name)
            response = meth(req, response)

        return response

    def _open(self, req, data=None):
        result = self._call_chain(self.handle_open, 'default',
                                  'default_open', req)
        if result:
            return result
        protocol = req.type
        result = self._call_chain(self.handle_open, protocol, protocol +
                                  '_open', req)
        if result:
            return result
        return self._call_chain(self.handle_open, 'unknown',
                                'unknown_open', req)

class BaseHandler:
    handler_order = 500

    def add_parent(self, parent):
        self.parent = parent

    def __lt__(self, other):
        if not hasattr(other, "handler_order"):
            return True
        return self.handler_order < other.handler_order


class AbstractHTTPHandler(BaseHandler):

    def __init__(self, debuglevel=None):
        self._debuglevel = debuglevel if debuglevel is not None else http.client.HTTPConnection.debuglevel

    def do_request_(self, request):
        host = request.host

        sel_host = host
        if not request.has_header('Host'):
            request.add_unredirected_header('Host', sel_host)
        for name, value in self.parent.addheaders:
            name = name.capitalize()
            if not request.has_header(name):
                request.add_unredirected_header(name, value)

        return request


if hasattr(http.client, 'HTTPSConnection'):
    class HTTPSHandler(AbstractHTTPHandler):
        def __init__(self, debuglevel=None, context=None, check_hostname=None):
            debuglevel = debuglevel if debuglevel is not None else http.client.HTTPSConnection.debuglevel
            AbstractHTTPHandler.__init__(self, debuglevel)
            if context is None:
                http_version = http.client.HTTPSConnection._http_vsn
                context = http.client._create_https_context(http_version)
            if check_hostname is not None:
                context.check_hostname = check_hostname
            self._context = context

        https_request = AbstractHTTPHandler.do_request_
    

opener = OpenerDirector()
opener.add_handler(HTTPSHandler())

myURL = opener.open("https://www.runoob.com/", data=None, timeout=socket._GLOBAL_DEFAULT_TIMEOUT)
content = myURL.read()
# content = request.urlopen("https://www.baidu.com/").read()
with open("test.html", "wb") as f:
    f.write(content)