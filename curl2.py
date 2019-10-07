import re
import socket
import ssl
import sympy
import urllib
from sympy.parsing.sympy_parser import parse_expr
from functools import partial
from bs4 import BeautifulSoup
import os
import threading
from multiprocessing import Process, Lock, Manager
#import concurrent.futures
from threading import Thread
import sys
import time
import queue
from datetime import datetime, timedelta
import sys

MAX_THREADS = 100

URL_REGEX = r"(http|https):\/\/([a-zA-Z\.]*\.(edu|net|com|org|info))(:\d*)?([a-zA-Z0-9\/\.\-\_\~\!\$\&\'\(\)\*\+\,\;\=\:\@]*)"
SHORT_URL_REGEX = r"[\"']\/([a-zA-Z0-9\/\.\-\_\~\!\$\&\'\(\)\*\+\,\;\=\:\@]+)[\"']"

proto_dict = {}


proto_dict['http'] = 80
proto_dict['https'] = 443
proto_dict['ftp'] = 21

class Requests:
    req_txt = ""                    \
    "%s %s HTTP/%s\r\n"             \
    "Host: %s\r\n"                  \
    "User-Agent: %s\r\n"            \
    "Accept: text/html\r\n"         \
    "Accept-Language: en-US,en;q=0.5\r\n" \
    "Accept-Encoding: plaintext\r\n" \
    "Connection: keep-alive\r\n"
    url = "/"
    hostname = "localhost"
    verb = "POST"
    data = ""
    uagent = "curl/7.64.1"
    ver = "1.1"
    timeout = 5
    resp_txt = b''
    resp = None
    def __init__(self, verb: str, url: str,
                ver: str, host: str, port: int,
                uagent: str, data: str):

        url = url.replace("//", "/")
        if(str(port) == "443" or str(port) == "80"):
            port_str = ""
        else:
            port_str = str(port)
        self.req_txt = self.req_txt % (verb, url, ver, host + port_str, uagent)
        if data is not "":
            self.req_txt += "Content-Length: %d\r\n" % int(len(data))
            self.req_txt += "Content-Type: %s\r\n" % "application/x-www-form-urlencoded"

        self.url = url
        self.hostname = host
        self.req_txt += "\r\n"
        if data is not "":
            self.req_txt += data

        if port == 80:
            self.resp_txt = self.sendit(self.req_txt, host, 80)
        elif port == 443:
            self.resp_txt = self.ssl_sendit(self.req_txt, host, 443)
        else:
            self.resp_txt = self.sendit(self.req_txt, host, int(port.replace(":","")))


    def sendit(self, txt: str, host: str, port: int):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)
        s.settimeout(self.timeout)
        host_ip = socket.gethostbyname(host)
        res = {}
        res['header'] = b''
        res['data'] = b''
        res['len'] = b''

        s.connect((host_ip, int(port)))
        s.send(txt.encode('utf-8'))
        data = b''
        try:
            data = s.recv(4096)
            while(data):
                res['header'] += data
                if(res['header'].endswith(b'\r\n\r\n')):
                    break
                data = s.recv(4096)

            # Receieve data
            data = s.recv(4096)
            while(len(data) > 0):
                res['data'] += data
                if(res['data'].endswith(b'\r\n\r\n')):
                    break
                data = s.recv(4096)
        except:
            print("err...")

        s.close()
        return res

    def ssl_sendit(self, txt: str, host: str, port: int):
        #print(txt)
        context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
        context.set_ciphers('ALL')
        host_ip = socket.gethostbyname(host)
        res = {}
        res['header'] = b''
        res['data'] = b''
        res['len'] = b''
        with socket.create_connection((host, 443)) as sock:
            with context.wrap_socket(sock, server_hostname=host) as s:
                s.send(txt.encode('utf-8'))
                try:
                    data = s.recv(1)
                    while(data):
                        res['header'] += data
                        if(res['header'].endswith(b'\r\n\r\n')):
                            break
                        data = s.recv(1)

                    # Receieve data
                    data = s.recv(120000)
                    while(len(data) > 0):
                        res['data'] += data
                        if(res['data'].endswith(b'\r\n\r\n')):
                            break
                        data = s.recv(4096)
                except:
                    print("err...")

        return res

    def post(url: str, data: str="", agent: str="IE"): # -> Response:
        arr = re.findall(URL_REGEX, url)[0]
        #print(arr)
        proto = arr[0]
        host = arr[1]
        port = proto_dict[arr[0]]
        if(arr[3] != ''):
            port = arr[3]
        path = arr[4]+'/'
        #print(port)
        return Requests("POST", path, "1.1", host, port, agent, data)

    def get(url: str, data: str="", agent: str="curl"): #-> Response:
        print(url)
        arr = re.findall(URL_REGEX, url)
        print(arr)
        if(len(arr) > 0):
            arr = arr[0]
        if(len(arr) < 3):
            print("[-] Error no url")
            return None
        proto = arr[0]
        host = arr[1]
        port = proto_dict[arr[0]]
        if(arr[3] != ''):
            port = arr[3]
        path = arr[4]
        return Requests("GET", "/"+path, "1.1", host, port, agent, data)



if __name__ == "__main__":

    print(sys.argv[1])
    url = sys.argv[1]
    try:
        print(url)
        r = Requests.get(url)
        print(r.req_txt)
    except Exception as e:
        print("\n\n===========================")
        print(url)
        print("===========================")
        print(e)
        print("===========================\n\n")
        sys.exit()
    print(r.resp_txt)
