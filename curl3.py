#!/usr/bin/env python3
from datetime import datetime, timedelta
from typing import List
from multiprocessing import Process, Lock, Manager, Queue
import re
import os
import socket
import ssl
import urllib
import signal
import sys
import time
from copy import copy

FLAG_VERBOSE = False

URL_REGEX = r"(http|https):\/\/([a-zA-Z\.]*\.(edu|net|com|org|info))(:\d*)?([a-zA-Z0-9\/\.\-\_\~\!\$\&\'\(\)\*\+\,\;\=\:\@\?]*)"

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
    def __init__(self, req):
#        if(not hdr_n_data): return()
        in_hdr = req.res['header'].split("\r\n")
        in_dat =  req.res['data']
        resp_tmp = re.findall(r'HTTP\/(\d\.\d) (\d{3}) (.*)', in_hdr[0])[0]

        # Save first line data
        self.ver = resp_tmp[0]
        self.status_code = resp_tmp[1]
        self.status_text = resp_tmp[2]

        self.resp['header'] = in_hdr
        self.resp['data'] = in_dat


        for i in in_hdr[1:]:
            line = i.split(": ")
            if(len(line) == 2):
                self.hdr_options[str(line[0])] = line[1]

        return None

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
    port = 80
    secure = False
    resp = None

    res = {}
    res['header'] = b''
    res['data'] = b''

    def __init__(self, verb: str, url: str,
                ver: str, host: str, port: int,
                uagent: str, data: str, secure: bool):
        
        url = url.replace("//", "/")
        if ":" not in str(port):
            port = ":"+str(port)
        
        if(":443" == str(port) or ":80" == str(port)):
            port_str = ""
        else:
            port_str = str(port)

        self.req_txt = self.req_txt % (verb, url, ver, host + port_str, uagent)

        if data is not "":
            self.req_txt += "Content-Length: %d\r\n" % int(len(data))
            self.req_txt += "Content-Type: %s\r\n" % "application/x-www-form-urlencoded"

        self.secure = secure
        self.port = port
        self.url = url
        self.hostname = host
        self.req_txt += "\r\n"

        if data is not "":
            self.req_txt += data

        send_res = self.sendit()


    def sendit(self):
        context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
        context.set_ciphers('ALL')
        host_ip = socket.gethostbyname(self.hostname)

        sock = None
        s = None
        if self.secure:
            sock = socket.create_connection((self.hostname, int(self.port.replace(":", ""))))
            s = context.wrap_socket(sock, server_hostname=self.hostname)
        else:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)
            s.connect((self.hostname, int(self.port.replace(":", ""))))

        s.send(self.req_txt.encode('utf-8'))
        data = b''
        tmp = b''
        try:
            tmp = s.recv(4096)
            while(tmp != b''):
                data += tmp
                tmp = s.recv(4096)
            data = data.decode('utf-8').split('\r\n\r\n')
            self.res['header'] = data[0]
            self.res['data'] = data[1]
        except Exception as e:
            if sock:
                sock.close()
            if s:
                s.close()
            if FLAG_VERBOSE:
                print("=====")
                print("[%s] Error recieving bytes:\n%s" % (os.getpid(), self.req_txt.encode('utf-8')) )
                print("=====")
                print("[%s] %s" % (os.getpid(), self.resp_txt.encode('utf-8')))
                print("=====")
                print("[%s] Error: %s" (os.getpid(), str(e)))
                print("=====")
        if sock:
            sock.close()
        if s:
            s.close()
        
        return self.res
  
    def get(url: str, data: str="", agent: str="curl"): #-> Response:
        secure = False
        arr = re.findall(URL_REGEX, url)

        if(len(arr) > 0):
            arr = arr[0]

        if(len(arr) < 3):
            print("[-] Error no url")
            return None

        proto = arr[0]
        host = arr[1]
        if(arr[0] == "https"):
            secure = True
        port = proto_dict[arr[0]]
        if(arr[3] != ''):
            port = arr[3]
        path = arr[4]
        
        return Response(Requests("GET", "/"+path, "1.1", host, port, agent, data, secure))


class Crawler():
    visited = None
    found_emails = None
    work_queue = None

    EMAIL_REGEX = r"([a-zA-Z0-9\.!#$%&'*+\/=?^_`{|}~-]+@[a-zA-Z0-9\.\-]+\.[a-zA-Z]{2,})"
    URL_REGEX = r"(http|https):\/\/([a-zA-Z\.]*\.([a-zA-Z]{2,24}))(:\d*)?([a-zA-Z0-9\/\.\-\_\~\!\$\&\'\(\)\*\+\,\;\=\:\@\?]*)"
    URL_REGEX_NO_ARGS = r"(http|https):\/\/([a-zA-Z\.]*\.([a-zA-Z]{2,24}))(:\d*)?([a-zA-Z0-9\/\.\-\_\~\!\$\&\'\(\)\*\+\,\;\=\:\@]*)"

    MAX_WORKERS = 5
    MAX_EMAILS = 1200

    # Number of seconds to wait with an empty queue before closing down workers
    TIMEOUT_DELAY = 10

    can_exit = False
    kill_signaled = False
    max_depth = 0
    start_url = ""
    scope = r""
    def __init__(self, start_url: str, scope: str, max_depth: int):
        self.manager = Manager()

        self.start_url = start_url
        self.scope = scope        
        self.max_depth = max_depth

        # Local copies of the variables
        self.visited = {}#self.manager.dict()
        self.found_emails = {}#self.manager.dict()

        # Outbound and inbound job queues
        # Workers pass back what sites have been visited so dispatcher can copy them into the local dict
        self.visited_queue = Queue()
        # Dispatcher passes the work_queue forward and between workers to find next urls
        self.work_queue = Queue()
        # Workers pass back emails they've found to the dispatcher
        self.email_queue = Queue()

        signal.signal(signal.SIGINT, self.signal_handler)

    """signal_handler(sig, frame) - Handle control signals being sent to program

    Handle control-C by setting kill_signaled variable
    """
    def signal_handler(self, sig, frame):
        print("Keyboard interrupt\nExiting....")
        self.kill_signaled = True
        # Clear the work_queue
        while(not self.work_queue.empty()):
            self.work_queue.get()

        sys.exit(1)
    
    def try_shutdown():
        last_check = datetime.now()
        while(self.work_queue.empty()):
            if(datetime.now() - last_check >= timedelta(seconds=self.TIMEOUT_DELAY)):
                print("Gracefully shutting down")
                self.can_exit = True
                work_queue.close()
                break

    def force_shutdown():
        print("Forceful shutdown")
        dump_queue(self.work_queue)
        self.can_exit = True
        self.work_queue.close()

    """dump_queue(self, queue: Queue) -> List - dump the contents of a queue

    Empties a queue. Copies the contents into a List.
    @return A List version of the contents of the Queue
    """
    def dump_queue(self, queue: Queue) -> List:
        res = []
        print("Dumbing the queue")
        # While the queue is not empty copy items to List
        while(not queue.empty()):
            res.append(self.work_queue.get())
        return res

    """worker_watcher() - Show the current status of crawler

    Loop constantly and show the number of collected emails, and number of urls scanned.
    """
    def worker_watcher(self):
        while(True):
            print("watching...")
            # Check if kill all workers signal should be sent (max emails, work_queue empty, ctrl-C)
            if(len(self.found_emails) > self.MAX_EMAILS or self.can_exit):
                # Clear the work_queue
                dump_queue(self.work_queue)
                force_shutdown()
                break
            #print("Watcher")
            print(self.visited_queue.get())
            print(self.email_queue.get())
            # Pass messages from queues to local data structures
            arr = self.dump_queue(self.visited_queue)
            for i in arr:
                self.visited[i] = self.getDepth(i)

            arr = self.dump_queue(self.email_queue) 
            for i in arr:
                j = i.split(" ")
                self.found_emails[j[0]] = j[1]
            
            print(self.found_emails)
            print(self.visited)   

            # Report on current work status
            print("mon[%s] Visited %d sites" % (os.getpid(), len(self.visited)))
            print("mon[%s] Collected %d emails" % (os.getpid(), len(self.found_emails)))
            time.sleep(5)

    """worker_dispatch() - Spawn workers and provide them with jobs

    Spawn MAX_WORKERS number of Processes to crawl.
    If kill is sent or success conditions are met gracefully shutdown all remaining Processes.
    While processes are running monitor their progress by printing diagnostics
    """
    def worker_dispatch(self):
        workers = []
        # Start monitor
        monitor_process = Process(target=self.worker_watcher, args=())
        monitor_process.start()

        # Put start_url in work_queue
        if(self.work_queue.empty()): self.work_queue.put(self.start_url)

        # Give the work_queue a second to put the new job on
        while(self.work_queue.empty()):
            time.sleep(.01)

        # Spawn MAX_WORKERS number of workers
        while(len(workers) < self.MAX_WORKERS):
            p = None
            try:
                # Init a worker
                p = Process(target=self.worker, args=())
                # Add worker to workers List so we can close them down later
                workers.append(p)
                # Start a worker
                p.start()
                # Wait a one hundreth of a second so our threads don't crash
            except Exception as e:
                print("Failed to start new proc, waiting 1 second")
                time.sleep(1)
            
            time.sleep(1)
            # Only start workers while the queue is not empty
            while(self.work_queue.empty()):
                time.sleep(.1)

        print(len(workers))            
        # Iterate through all workers
        for i in workers:
            # Wait for proc to close
            p.join()
        monitor_process.join()
        print("Exiting...")

    """worker() - Worker are the functions running each thread.

    Each thread will pull a job (url) from the queue.
    After pulling a new job it will crawl the page using the crawl_page function.
    After crawling it will mark the job as done.
    """
    def worker(self):
        # Loop until told not to
        while(not self.can_exit):
            try:
                # Get a job
                job = ""

                # Make sure it hasn't been visited before
                # If job is already in visited keep getting new ones.
                # Make sure job meets our scope/depth (also checked in crawl_page)
                while(job in self.visited or not self.check_scope(job, self.scope) or not self.check_depth(job, self.max_depth) or job is None):
                    job = self.work_queue.get()
                
                print( "[%s] %s" % (str(os.getpid()), job) )
                # Crawl the page extracting url and emails
                self.crawl_page(job)
            except IndexError as e:
                print( "[%s] List is empty... waiting %d seconds" % (str(os.getpid()), self.TIMEOUT_DELAY) )
                self.try_shutdown()
            # Repeat

    """crawl_page(self, url: str="") - Crawl a page for URLs and emails

    Download a page.
    Add the page to the visited dict.
    Extract all url from page
    Iterate through all urls on the page.
    Check that they match scope and depth.
    Add the verified url to the work queue.

    Extract all emails from page
    Iterate through all emails, add them to found_emails dict.
    @return List of emails found in page
    """
    def crawl_page(self, url: str="") -> List:
        # If the url argument is not set assume start of crawling
        if url == "": url = self.start_url
        # Load the page in question
        r = Requests.get(url)
        # Add url to visited (so we don't revisit it)
        self.visited[url] = self.getDepth(url)
        # Iterate through and add all urls
        for i in self.extract_urls(r.resp['data']):
            # Build url string for new links given regex extraction 
            j = "%s://%s%s" % (i[0], i[1], i[4])
            # Make sure new url fits our scope and max depth before adding it to the work queue
            if self.check_scope(j, self.scope) and self.check_depth(j, self.max_depth):
                # Check if url is in work queue
                if j not in self.visited:
                    # Add new url to the work queue for another worker to pick up
                    if FLAG_VERBOSE: print("[%s] Adding to work queue: %s" % (os.getpid(), j))
                    self.work_queue.put(j)
        
        # Extract emails from the loaded page
        arr_emails = self.extract_email(r.resp['data'])
        # Iterate through each
        for k in arr_emails:
            # Put extracted email with the depth it was found at on queue
            self.email_queue.put("%s %d" % (str(k), self.getDepth(k)))
        time.sleep(.5)
        # Return the emails that were found
        return self.found_emails

    """extract_email(self, doc: str) -> List - Extract a list of email address

    Extracts all emails into a List using the EMAIL_REGEX string.
    @return array of emails found in page
    """
    def extract_email(self, doc: str) -> List:
        arr = re.findall(self.EMAIL_REGEX, doc)
        return arr

    """extract_urls(self, doc: str) -> List - Extract a list of url address
    
    Extracts all urls into a List using the URL_REGEX string.
    @return array of urls found in page
    """
    def extract_urls(self, doc: str) -> List:
        arr = re.findall(URL_REGEX, doc)
        return arr

    """check_scope(self, target: str, scope: str = URL_REGEX) -> bool - returns True if target fits the scope
    
    Tries to match target to regex string. If it does return True
    @return True if the target matches the scope, False if it does not
    """
    def check_scope(self, target: str, scope: str = URL_REGEX) -> bool:
        arr = re.findall(scope, target)
        # If findall finds anything return True
        if(len(arr) > 0):
            return True
        return False

    """check_depth(self, target: str, max_depth: int = 4) -> bool - Check if target url is within max_depth

    @return True if the depth is less than max_depth, otherwise, False
    """
    def check_depth(self, target: str, max_depth: int = 4) -> bool:
        return self.getDepth(target) < max_depth

    """getDepth(self, target: str) -> int - Get the depth of a url.

    Measures the depth of both urls and simple file paths.
    If it matches a url (w/o arguments prevents things like http://example.com/a?url="http://notexample.com/more/depth/" from counting) 
    Removes excessive "//" to prevent messing with measurement.
    @return number of directories deep of the url
    """
    def getDepth(self, target: str) -> int:
        # Remove excessive '/'
        target = target.replace("//", "")
        # Remove tailing '/'
        if(target.endswith("/")): target = target[:-1]
        # Check if target is a url
        arr = re.findall(self.URL_REGEX_NO_ARGS, target)
        if(len(arr) > 0):
            # If True reset target to just file path
            target = arr[0][4]
        # Measure number of slashes found
        return len(target.split('/'))-1


SCOPE_REGEX = r"[http|https]\:\/\/www\.rit\.edu.*"
if __name__ == "__main__":
    #url = "https://www.rit.edu/directory?term_node_tid_depth=All"
    url = "https://www.rit.edu/"
    c = Crawler(url, SCOPE_REGEX, 4)
    print(c.worker_dispatch())