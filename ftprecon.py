#!/usr/bin/env python
import subprocess
import sys

if len(sys.argv) != 3:
    print "Usage: ftprecon.py <ip address> <port>"
    sys.exit(0)

ip_address = sys.argv[1].strip()
port = sys.argv[2].strip()
print "INFO: Performing nmap FTP script scan for " + ip_address + ":" + port
FTPSCAN = "nmap -sV -Pn -vv -p %s --script=ftp-anon,ftp-bounce,ftp-libopie,ftp-proftpd-backdoor,ftp-vsftpd-backdoor,ftp-vuln-cve2010-4221 -oN '/root/scripts/recon/recon2/results/lab2018/%s_ftp.nmap' %s" % (port, ip_address, ip_address)
results = subprocess.check_output(FTPSCAN, shell=True)
outfile = "/root/scripts/recon/recon2/results/lab2018/" + ip_address + "_ftprecon.txt"
f = open(outfile, "w")
f.write(results)
f.close

print "INFO: Performing hydra ftp scan against " + ip_address 
HYDRA = "hydra -L /root/scripts/recon/recon2/wordlists/userlist -P /root/scripts/recon/recon_enum/wordlists/offsecpass -f -o /root/recon/recon_enum/results/%s_ftphydra.txt -u %s -s %s ftp" % (ip_address, ip_address, port)
results = subprocess.check_output(HYDRA, shell=True)
resultarr = results.split("\n")
for result in resultarr:
    if "login:" in result:
	print "[*] Valid ftp credentials found: " + result 
