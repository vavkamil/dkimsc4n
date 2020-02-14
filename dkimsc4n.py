#!/usr/bin/python

import os
import re
import sys
import argparse
from dns import resolver
import concurrent.futures
from random import shuffle
from base64 import b64decode
from termcolor import colored
from Crypto.PublicKey import RSA

def banner():
    print("""______ _   __________  ___           ___       
|  _  \ | / /_   _|  \/  |          /   | v0.1
| | | | |/ /  | | | .  . |___  ___ / /| |_ __
| | | |    \  | | | |\/| / __|/ __/ /_| | '_ \ 
| |/ /| |\  \_| |_| |  | \__ \ (__\___  | | | |
|___/ \_| \_/\___/\_|  |_/___/\___|   |_/_| |_|\n""")

def parse_args():
    parser = argparse.ArgumentParser(description="Asynchronous wordlist based DKIM scanner", epilog="Created by @vavkamil ~ https://github.com/vavkamil")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-d", dest="domain", help="single domain name to scan")
    group.add_argument("-D", dest="domains", help="list of domains to scan", type=argparse.FileType('r'))
    parser.add_argument("-w", dest="wordlist", help="wordlist with dkim selectors (default: dkim.lst)", default="dkim.lst", type=argparse.FileType('r'))
    parser.add_argument("-n", dest="nameservers", help="wordlist with nameservers (default: nameservers.lst)", default="nameservers.lst", type=argparse.FileType('r'))
    parser.add_argument("-o", dest="output", help="save output to a file (csv separated by semicolon)", type=argparse.FileType('a'))
    parser.add_argument("-t", dest="threads", help="number of threads (default: 5)", default="5", type=int)
    return parser.parse_args()

def load_dkim_wordlist(location):
    selectors = []
    with location as dkim_wordlist:
        for selector in dkim_wordlist:
            if selector.strip() != '':
                selectors.append(selector.strip())
    if not selectors:
        print ("Error no selectors were found in the file")
    return selectors

def load_nameservers(location):
    data = []
    with location as nameserverslist:
    	for line in nameserverslist:
            line = line.strip()
            if line != '':
                data.append(line)
    if not data:
        print ("Error nameservers were found in the file")
    return data

def load_domains(location):
    domains = []
    with location as domainlist:
        for domain in domainlist:
            if domain.strip() != '':
                domains.append(domain.strip())
    if not domains:
        print ("Error no domains were found in the file")
    return domains


def check_dkim_record(selector, domain):
    res = resolver.Resolver()
    global nameservers
    shuffle(nameservers)
    res.nameservers = nameservers

    try:
        answers = res.query(selector+"._domainkey."+domain, "TXT")
    except (resolver.NoAnswer, resolver.NXDOMAIN):
        answers = []
    if len(answers) > 1:
        # print (colored("\n[*] Error: selector: "+selector+" for domain: "+domain+" is misconfigured (received more than one DKIM back)", "magenta"))
        return (0, 0, 0, 0,0)
    elif not answers:
        pass
        return (0, 0, 0, 0,0)
    else:
        for rdata in answers:
            txt_string = str(b"".join(rdata.strings))
            dkim_type_p = re.findall(r'p=(.*?)(;|\s|$)',txt_string)
            if not(dkim_type_p):
                return (0, 0, 0, 0,0) # Can't apply my shitty regex
            else:
                asn_bytes = b64decode(str(dkim_type_p[0]))
                key_pub = RSA.importKey(asn_bytes)
                key_size = key_pub.size() + 1
        return (1, selector, domain, key_size,str(dkim_type_p[0]))

def scan_domain(domain):
    dkim_results = dict()
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as executor:
        dkim_record = {executor.submit(check_dkim_record, selector, domain): selector for selector in dkim_selectors}
        for dkim in concurrent.futures.as_completed(dkim_record):
            try:
                (check, selector, domain, key_size,dkim_type_p) = dkim.result()
            except Exception as exc:
                print (colored("\n[*] Error: "+str(exc), "magenta"))
            else:
                if(check == 1):
                    #print ("[i] Domain: "+'{:25}'.format(domain)+"\tDKIM selector: "+'{:15}'.format(selector))
                    s = {selector:{'key_size':key_size,'dkim_type_p':dkim_type_p}}
                    if domain in dkim_results:
                        # append the new number to the existing array at this slot
                        dkim_results[domain].append(s)
                    else:
                        # create a new array in this slot
                        dkim_results[domain] = [s]
                        
    return dkim_results

def check_results(dkim_results):
    for domain in dkim_results:
        print ("\n[i] Domain:", domain)
        for result in dkim_results[domain]:
            for selector in result:
                key_size = result[selector]['key_size']
                dkim_type_p = result[selector]['dkim_type_p']

                if key_size > 1024:
                    print (colored("\t[+] DKIM selector: "+'{:15}'.format(selector)+"\tRSA key size: "+str(key_size), "blue"))
                elif key_size == 768:
                    print (colored("\t[?] DKIM selector: "+'{:15}'.format(selector)+"\tRSA key size: "+str(key_size), "yellow"))
                elif key_size <= 512:
                    print (colored("\t[!] DKIM selector: "+'{:15}'.format(selector)+"\tRSA key size: "+str(key_size), "red"))
                else:
                    print ("\t[i] DKIM selector: "+'{:15}'.format(selector)+"\tRSA key size: "+str(key_size))

                if(args.output):
                    args.output.write(domain+","+selector+","+str(key_size)+","+dkim_type_p+"\n")
                    args.output.flush()

if __name__ == "__main__":
    banner()
    args = parse_args()
    dkim_results = dict()

    dkim_selectors = load_dkim_wordlist(args.wordlist)
    print ("[i] Using nameserverlist:", args.nameservers.name)
    print ("[i] Using wordlist:", args.wordlist.name)
    print ("[i] DKIM selectors in a wordlist:", str(len(dkim_selectors))+"\n")

    global nameservers
    if(args.nameservers):
        nameservers = load_nameservers(args.nameservers)

    if(args.output):
        print ("[i] Output will be saved to:", args.output.name+"\n")

    if(args.domain):
        domain = args.domain
        print ("[i] Scanning a single domain:", domain)
        dkim_results = scan_domain(domain)
        check_results(dkim_results)

    elif(args.domains):
        domains = load_domains(args.domains)
        print ("[i] Scanning multiple domains:", args.domains.name)
        print ("[i] Domains in a list:", str(len(domains)))
        for domain in domains:
            dkim_results = scan_domain(domain)
            check_results(dkim_results)

    print ("\n[!] Have a nice day ;)\n")
