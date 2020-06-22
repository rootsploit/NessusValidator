import csv
import time
import os

file1=input("Enter Nessus Report File Name > ")
file2=os.path.splitext(file1)[0]

#---------------- Sort SSl ----------------
maindata = []
with open(file1, 'r') as inp:   
    for row in csv.reader(inp):
        if row[7].startswith("SSL") or row[7].startswith("OpenSSL") or row[7].endswith("TLS"):
            maindata.append((str(row[4]), str(row[6])))

#---------------- Adding unique ports to IP ----------------
ip_addr = {}
for line in maindata:
    ip,port=line[0], line[1]
    if ip in ip_addr.keys():
        if port not in ip_addr[ip]:
            ip_addr[ip].append(port) 
    else:
        ip_addr[ip] = [port]

#---------------- Nmap Scan ----------------
for ip in ip_addr:
    if ip_addr[ip] is not None:
        removeChars = "[] '"
        ports = str(ip_addr[ip])
        for char in removeChars:
            ports=ports.replace(char, "")
        cmd = "nmap -Pn -sV --script ssl-enum-ciphers {1} -p {0} -oX {2}_{1}.xml".format(ports,ip,file2)            
        print (cmd)