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

class Response:
    proto = "http"
    ver = ""
    status_code = 0
    status_text = ""


    resp = {}
    hdr_options = {}
    date = ""
    server = ""
    cont_len = 0
    vary = ""
    cont_type = ""
    data = ""
    def __init__(self, hdr_n_data):
#        if(not hdr_n_data): return()
        in_hdr = hdr_n_data['header'].split(b'\r\n')
        in_dat =  hdr_n_data['data']
        resp_tmp = re.findall(r'HTTP\/(\d\.\d) (\d{3}) (.*)', in_hdr[0].decode("utf-8"))[0]

        # Save first line data
        self.ver = resp_tmp[0]
        self.status_code = resp_tmp[1]
        self.status_text = resp_tmp[2]

        self.resp['header'] = in_hdr
        self.resp['data'] = in_dat


        for i in in_hdr[1:]:
            line = i.decode("utf-8").split(": ")
            if(len(line) == 2):
                self.hdr_options[str(line[0])] = line[1]

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
            data = s.recv(1)
            while(data):
                res['header'] += data
                if(res['header'].endswith(b'\r\n\r\n')):
                    break
                data = s.recv(1)

            # Receieve data
            data = s.recv(1)
            while(len(data) > 0):
                res['data'] += data
                #if(res['data'].endswith(b'\xff/') or res['data'].endswith(b'\x0e\x00')):
                #                               ''          added weird binary strings to catch a few outliers...
                if(res['data'].endswith(b'\r\n\r\n') or res['data'].endswith(b'\xff/') or res['data'].endswith(b'\x0e\x00')):
                    break
                data = s.recv(1)
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
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                ssock.send(txt.encode('utf-8'))
                '''
                data = ssock.recv(4096)
                while(data != b''):
                    res['data'] += data
                    data = ssock.recv(4096)
                '''
                    
                # Recieve header
                data = ssock.recv(1)
                while(data):
                    res['header'] += data
                    if(res['header'].endswith(b'\r\n\r\n')):
                        break
                    data = ssock.recv(1)
    
                # Recive middle section - length?
                #data = ssock.recv(1)
                #while(data):
                    #print(data)
                #    res['len'] += data
                #    if(res['len'].endswith(b'\r\n')):
                #        break
                #    data = ssock.recv(1)

                # Receieve data
                data = ssock.recv(1)
                while(len(data) > 0):
                    res['data'] += data
                    #if(res['data'].endswith(b'\r\n\r\n')):
                    if(len(res['data']) > 120000):
                        break
                    data = ssock.recv(4096)

        #if(len(res['data']) == 0):
        #    res['data'] = res['len'] + res['data']
        #print(res['data'])
        return res

    def post(url: str, data: str="", agent: str="IE") -> Response:
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

    def get(url: str, data: str="", agent: str="IE") -> Response:
        print(url)
        arr = re.findall(URL_REGEX, url)
        #print(arr)
        if(len(arr) > 0):
            arr = arr[0]
        if(len(arr) < 4):
            print("[-] Error no url")
            return None
        proto = arr[0]
        host = arr[1]
        port = proto_dict[arr[0]]
        if(arr[3] != ''):
            port = arr[3]
        path = arr[4]
        return Requests("GET", "/"+path, "1.1", host, port, agent, data)


def do_image_stuff(img):
    #print(img)
    #print(img['data-src'])
    img_req = Requests.get(img['data-src'])
    #print(img_req)
    img_resp = Response(img_req.resp_txt)


    if(int(img_resp.status_code) == 302):
        img_req = Requests.get("https://"+img_req.hostname+'/'.join(img_req.url.split("/")[:-1])+"/"+img_resp.hdr_options["Location"])
        img_resp = Response(img_req.resp_txt)
    if(int(img_resp.status_code) == 400):
        img_req = Requests.get("".join([img['data-src'].split()[0], img['data-src'].split()[2]]))
        img_resp = Response(img_req.resp_txt)
    print(img_resp.status_code)


    #print(img_resp.resp['data'])
    f = open("./images/"+img['alt']+".jpg", "wb+")
    f.write(img_resp.resp['data'])
    f.close()


def get_links_from_urls(url, r_scope=r".*"):
    try:
        r = Requests.get(url)
    except Exception as e:
        print("\n\n===========================")
        print(url)
        print("===========================")
        print(e)
        print("===========================\n\n")
        return -1
    resp = Response(r.resp_txt)
    document = BeautifulSoup(resp.resp['data'], "html.parser")
    arr = re.findall(r_scope, str(r.resp_txt))
    #arr1 = re.findall(r"([a-zA-Z0-9.!#$%&'*+\/=?^_`{|}~-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})", str(document))
    arr1 = re.findall(r"([a-zA-Z0-9\.!#$%&'*+\/=?^_`{|}~-]+@[a-zA-Z0-9\.\-]+\.[a-zA-Z]{2,})", str(document))
    #arr1 = re.findall(r"mailto:([a-z0-9A-Z\-@.]+)", str(document))
    #for line in str(document).split('\n'):
    #    if "@" in line:
    #        print(line)
    #for i in document.findaAll('a'):
    #    if i.has_attr('href'): print(i['href'])
    arr2 = re.findall(SHORT_URL_REGEX, str(document))
    #print(arr1)
    return (arr, arr1, arr2)

def extract_emails(doc):
    arr = re.findall()

def getDepthUrl(url, scope):
    arr = re.findall(URL_REGEX, url)[0]
    return len(arr[4].split('/'))-1

def getDepthPath(path):
    return len(path.split('/'))-1

def worker(visited, links, scope, depth, emails):
    try:
        exit = False
        while(not exit):
            last_check = datetime.now()
            # May have to add a max queue size
            while(len(links) <= 0):
                if(datetime.now() - last_check >= timedelta(seconds=500)):
                    print("Queue empty")
                    exit = True
                    break
            while True:
                try:
                    url = links.pop()
                    break
                except:
                    waste = 1
            #print(url)
            if("KILL" in links): 
                exit = True
                break
            #print("[%s] reading page: %s" % (threading.current_thread().name, url))
            base = re.findall(URL_REGEX, url)[0]
            base_str = str(base[0]+"://"+base[1]+base[3]+base[4])

            res_arr = get_links_from_urls(url, scope)
            tmp_arr = res_arr[0]
            email_arr = res_arr[1]
            for x in res_arr[2]:
                if str(base_str)+str(x) not in list(links) and str(base_str)+str(x) not in list(visited) and getDepthPath(str(x)) < depth:
                    #print(base_str)
                    links.append(str(base_str)+str(x))
            cur_depth = getDepthUrl(url, URL_REGEX)
            j = 0
            for i in tmp_arr:
                if str(i[0]+"://"+i[1]+i[2]+i[3]) not in list(links) and str(i[0]+"://"+i[1]+i[2]+i[3]) not in list(visited) and getDepthPath(i[3]) < depth:
                    j+=1
                    links.append(i[0]+"://"+i[1]+i[2]+i[3])


            for i in email_arr:
                print("Adding %s" % i)
                emails[i] = cur_depth

            #print(emails)
            visited.append(url)
        print("Exiting proc")
    except Exception as e:
        print("Worker died....")
        print(e)

proc_arr = []
def dispatcher(links, visited, scope, depth, emails):
    for i in range(MAX_THREADS):
        while(len(links) < i):
            trash = 1
        print("Starting worker")
        #p = Process(target=f, args=('bob',))
        p = Process(target=worker, args=(visited, links, scope, depth, emails,))
        proc_arr.append(p)
        #p.setDeamon(True)
        p.start()
        #worker(visited, links, scope, depth)

    #for i in proc_arr:
    #    i.join()

if __name__ == "__main__":
    manager = Manager()
    links = manager.list()
    visited = manager.list()
    emails = manager.dict()

    depth = 8
    scope = r"(http|https):\/\/(www\.rit\.edu)(:\d*)?([a-zA-Z0-9\/\.\-\_\~\!\$\&\'\(\)\*\+\,\;\=\:\@]*)"
    

    print(sys.argv[1])
    url = sys.argv[1]
    #url = "https://www.rit.edu/directory?term_node_tid_depth=All"
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
    resp = Response(r.resp_txt)
    #print(resp.resp['data'])

    #print(resp)
    document = BeautifulSoup(resp.resp['data'], "html.parser")
    print(str(document))
    sys.exit()

    '''
    #url = sys.argv[1]
    url = "https://www.rit.edu/directory?term_node_tid_depth=All"
    '''

    print(get_links_from_urls(url, scope)[1])
    sys.exit()




    #links.append("https://www.rit.edu/")
    links.append("https://www.rit.edu/directory?term_node_tid_depth=All")
    dispatcher(links, visited, scope, 4, emails)

    while(True):
        print(len(links))
        print(len(emails))
        print(emails)
        time.sleep(1)
        if(len(emails) >= 1200):
            print(links)
            print(len(links))
            links = list(dict(links))
            print(len(links))
            links *= 0
            for i in range(MAX_THREADS*2):
                #print(links)
                links.append("KILL")
                #print(links)
            for i in proc_arr:
                i.join()
                i.terminate()
            
            for i in range(depth):
                with open("depth_"+str(i)+".out", 'w+') as fp:
                    print(dict(emails))
                    for k in dict(emails):
                        if str(emails[k]) == str(i):
                            fp.write('%s\n' % k)
                fp.close()
            print("Yeet")
            sys.exit()
            

    
    


    # Get initial Queue
    links = queue.Queue()
    visited = queue.Queue()
    emails = queue.Queue()

    comp_arr = []
    with open("./companies.csv") as fp:
        count = 0
        line = fp.readline()
        while(line and count < 25):
            tmp = re.findall(URL_REGEX, line.split(',')[1])
            if(len(tmp) > 0): comp_arr.append(tmp[0])

            count +=1
            line = fp.readline()

    print(comp_arr)
    for i in comp_arr:
        scope = r"(http|https):\/\/(%s)(:\d*)?([a-zA-Z0-9\/\.\-\_\~\!\$\&\'\(\)\*\+\,\;\=\:\@]*)" % (i[1])
        links.put("%s://%s/%s" % (i[0], i[1],i[3]))
        print(list(links.queue))
        dispatcher(links, visited, scope, 4, emails)






    # Get initial Queue
    scope = r"(http|https):\/\/(www\.rit\.edu)(:\d*)?([a-zA-Z0-9\/\.\-\_\~\!\$\&\'\(\)\*\+\,\;\=\:\@]*)"
    links = queue.Queue()
    visited = queue.Queue()
    emails = queue.Queue()

    print(links.qsize())

    links.put("https://www.rit.edu/")
    dispatcher(links, visited, scope, 4, emails)
    #print(list(links.queue))
