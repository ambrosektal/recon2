#!/usr/bin/env python

###############################################################################################################
## [Title]: reconscan.py -- a recon/enumeration script
## [Author]: Mike Czumak (T_v3rn1x) -- @SecuritySift
##-------------------------------------------------------------------------------------------------------------
## [Details]: 
## This script is intended to be executed remotely against a list of IPs to enumerate discovered services such 
## as smb, smtp, snmp, ftp and other. 
##-------------------------------------------------------------------------------------------------------------
## [Warning]:
## This script comes as-is with no promise of functionality or accuracy.  I strictly wrote it for personal use
## I have no plans to maintain updates, I did not write it to be efficient and in some cases you may find the 
## functions may not produce the desired results so use at your own risk/discretion. I wrote this script to 
## target machines in a lab environment so please only use it against systems for which you have permission!!  
##-------------------------------------------------------------------------------------------------------------   
## [Modification, Distribution, and Attribution]:
## You are free to modify and/or distribute this script as you wish.  I only ask that you maintain original
## author attribution and not attempt to sell it or incorporate it into any commercial offering (as if it's 
## worth anything anyway :)
###############################################################################################################

import subprocess
import multiprocessing
from multiprocessing import Process, Queue
import os
import time
import threading
from queue import Queue
q = Queue()
print_lock = threading.Lock()
iplist = []

def multProc(targetin, scanip, port):
    jobs = []
    p = multiprocessing.Process(target=targetin, args=(scanip,port))
    jobs.append(p)
    p.start()
    return


#def dnsEnum(ip_address, port):
#    print "INFO: Detected DNS on " + ip_address + ":" + port
#    if port.strip() == "53":
#       SCRIPT = "./dnsrecon.py %s" % (ip_address)# execute the python script         
#       subprocess.call(SCRIPT, shell=True)
#    return

def httpEnum(ip_address, port):
    print "INFO: Detected http on " + ip_address + ":" + port
    print "INFO: Performing nmap web script scan for " + ip_address + ":" + port    
    HTTPSCAN = "nmap -sV -Pn -vv -p %s --script=http-vhosts,http-userdir-enum,http-apache-negotiation,http-backup-finder,http-config-backup,http-default-accounts,http-methods,http-method-tamper,http-passwd,http-robots.txt -oN /root/scripts/recon/recon_enum/results/lab2018/%s_http.nmap %s" % (port, ip_address, ip_address)
    results = subprocess.check_output(HTTPSCAN, shell=True)
    DIRBUST = "./dirbust.py http://%s:%s %s" % (ip_address, port, ip_address) # execute the python script
    subprocess.call(DIRBUST, shell=True)
    #NIKTOSCAN = "nikto -host %s -p %s > %s._nikto" % (ip_address, port, ip_address)
    return

def httpsEnum(ip_address, port):
    print "INFO: Detected https on " + ip_address + ":" + port
    print "INFO: Performing nmap web script scan for " + ip_address + ":" + port    
    HTTPSCANS = "nmap -sV -Pn -vv -p %s --script=http-vhosts,http-userdir-enum,http-apache-negotiation,http-backup-finder,http-config-backup,http-default-accounts,http-methods,http-method-tamper,http-passwd,http-robots.txt -oX /root/scripts/recon/recon_enum/results/lab2018/%s_https.nmap %s" % (port, ip_address, ip_address)
    results = subprocess.check_output(HTTPSCANS, shell=True)
    DIRBUST = "./dirbust.py https://%s:%s %s" % (ip_address, port, ip_address) # execute the python script
    subprocess.call(DIRBUST, shell=True)
    #NIKTOSCAN = "nikto -host %s -p %s > %s._nikto" % (ip_address, port, ip_address)
    return

def nmapScan(ip_address):
   ip_address = ip_address.strip()
   print "INFO: Running general TCP/UDP nmap scans for " + ip_address
   serv_dict = {}
   TCPSCAN = "nmap -vv -Pn -A -sC -sS -T 4 -p- -oN '/root/scripts/recon/recon_enum/results/lab2018/%s.nmap' -oX '/root/scripts/recon/recon_enum/results/lab2018/nmap/%s_nmap_scan_import.xml' %s"  % (ip_address, ip_address, ip_address)
   UDPSCAN = "nmap -vv -Pn -A -sC -sU -T 4 --top-ports 200 -oN '/root/scripts/recon/recon_enum/results/lab2018/%sU.nmap' -oX '/root/scripts/recon/recon_enum/results/lab2018/nmap/%sU_nmap_scan_import.xml' %s" % (ip_address, ip_address, ip_address)
   results = subprocess.check_output(TCPSCAN, shell=True)
   udpresults = subprocess.check_output(UDPSCAN, shell=True)
   lines = results.split("\n")
   for line in lines:
      ports = []
      line = line.strip()
      if ("tcp" in line) and ("open" in line) and not ("Discovered" in line):
         while "  " in line: 
            line = line.replace("  ", " ");
         linesplit= line.split(" ")
         service = linesplit[2] # grab the service name
	 port = line.split(" ")[0] # grab the port/proto
         if service in serv_dict:
	    ports = serv_dict[service] # if the service is already in the dict, grab the port list
	 
         ports.append(port) 
	 serv_dict[service] = ports # add service to the dictionary along with the associated port(2)
   
   # go through the service dictionary to call additional targeted enumeration functions 
   for serv in serv_dict: 
      ports = serv_dict[serv]	
      if (serv == "http"):
 	 for port in ports:
	    port = port.split("/")[0]
	    multProc(httpEnum, ip_address, port)
      elif (serv == "ssl/http") or ("https" in serv):
	 for port in ports:
	    port = port.split("/")[0]
	    multProc(httpsEnum, ip_address, port)
      
   print "INFO: TCP/UDP Nmap scans completed for " + ip_address 
   return

def target_file():
     f = open('/root/scripts/recon/recon_enum/results/targets.txt', 'r') # CHANGE THIS!! grab the alive hosts from the discovery scan for enum
     for scanip in f:
         iplist.append(str.strip(scanip))
     print(iplist)
     f.close()

def scanning_job():
    nmapScan(iplist[0])
    print(iplist[0], "scanning_job")
    iplist.remove(iplist[0])
    with print_lock:
        print(threading.current_thread().name)#, worker) #prevents the print from printing until unlocked

def threader(): #Actually performing the threading operation
    while True:
        worker = q.get() # getting the worker from the queue and putting the worker to work.
        scanning_job()
        q.task_done()

def starting_jobs():
   t = threading.Thread(target=threader)
   t.daemon = True #will die when the main thread dies
   t.start()
   print(iplist[0], "starting_jobs")

# grab the discover scan results and start scanning up hosts
print "############################################################"
print "####                      RECON SCAN                    ####"
print "####            A multi-process service scanner         ####"
print "####        http, ftp, dns, ssh, snmp, smtp, ms-sql     ####"
print "############################################################"
if __name__=='__main__':
    target_file()
#    for x in range(254): #workers
#    t = threading.Thread(target=threader)
#    t.daemon = True #will die when the main thread dies
#    t.start()
    for x in range(254):
        starting_jobs()

    start = time.time()

    for worker in range(20): ##20 instances of workers / how many total jobs to run.
        q.put(worker) #putting worker to work

    q.join() #waits till thread terminates

    print("Entire job took: ",time.time()-start)

    print("")



#scan(scanip):


#buildIPlist()

#while len(IPlist):
#    if Thread.enumerate().isAlive() < 3:
#        t = threading.Thread(target=nmapScan, args=IPlist[0])
#        t.daemon
#        t.start()
#        IPlist.remove(IPlist[0])




#scan(ip)
#checkVulns(ip)

#[
#    ['scan','192,168,1,1'],
#    ['scan','192.168.1.2'],
#    ['checkVulns','192.168.1.1']
#]
#list[0][0](


#test = 'scan'
#test('192.168.1.1') === scan('192.168.1.1')
