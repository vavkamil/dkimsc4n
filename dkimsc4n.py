#!/usr/bin/env python3

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
    print(
        """______ _   __________  ___           ___       
|  _  \ | / /_   _|  \/  |          /   | v0.2
| | | | |/ /  | | | .  . |___  ___ / /| |_ __
| | | |    \  | | | |\/| / __|/ __/ /_| | '_ \ 
| |/ /| |\  \_| |_| |  | \__ \ (__\___  | | | |
|___/ \_| \_/\___/\_|  |_/___/\___|   |_/_| |_|\n"""
    )


def parse_args():
    parser = argparse.ArgumentParser(
        description="Asynchronous wordlist based DKIM scanner",
        epilog="Created by @vavkamil ~ https://github.com/vavkamil",
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-d", dest="domain", help="single domain name to scan")
    group.add_argument(
        "-D",
        dest="domains",
        help="list of domains to scan",
        type=argparse.FileType("r"),
    )
    parser.add_argument(
        "-w",
        dest="wordlist",
        help="wordlist with dkim selectors (default: dkim.lst)",
        default="dkim.lst",
        type=argparse.FileType("r"),
    )
    parser.add_argument(
        "-o",
        dest="output",
        help="save output to a file (csv separated by semicolon)",
        type=argparse.FileType("w"),
    )
    parser.add_argument(
        "-t",
        dest="threads",
        help="number of threads (default: 5)",
        default="5",
        type=int,
    )
    return parser.parse_args()


def load_dkim_wordlist(location):
    selectors = []
    with location as dkim_wordlist:
        for selector in dkim_wordlist:
            if selector.strip() != "":
                selectors.append(selector.strip())
    if not selectors:
        print("Error no selectors were found in the file")
    return selectors


def load_domains(location):
    domains = []
    with location as domainlist:
        for domain in domainlist:
            if domain.strip() != "":
                domains.append(domain.strip())
    if not domains:
        print("Error no domains were found in the file")
    return domains


def check_dkim_record(selector, domain):
    res = resolver.Resolver()
    nameservers = ["8.8.8.8", "1.1.1.1", "8.8.4.4", "1.0.0.1"]
    shuffle(nameservers)
    res.nameservers = nameservers

    try:
        answers = res.resolve(selector + "._domainkey." + domain, "TXT")
    except (resolver.NoAnswer, resolver.NXDOMAIN):
        answers = []
    if len(answers) > 1:
        # print (colored("\n[*] Error: selector: "+selector+" for domain: "+domain+" is misconfigured (received more than one DKIM back)", "magenta"))
        return (0, 0, 0, 0)
    elif not answers:
        pass
        return (0, 0, 0, 0)
    else:
        for rdata in answers:
            txt_string = str(b"".join(rdata.strings))
            dkim_type_p = re.search(r"p=(.*?)('|;|\s|$)", txt_string)

            if not (dkim_type_p):
                return (0, 0, 0, 0)  # Can't apply my shitty regex
            else:
                asn_bytes = b64decode(str(dkim_type_p[1]))

                key_pub = RSA.importKey(asn_bytes)
                key_size = key_pub.size_in_bits()

        return (1, selector, domain, key_size)


def scan_domain(domain):
    dkim_results = dict()
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as executor:
        dkim_record = {
            executor.submit(check_dkim_record, selector, domain): selector
            for selector in dkim_selectors
        }
        for dkim in concurrent.futures.as_completed(dkim_record):
            try:
                (check, selector, domain, key_size) = dkim.result()
            except Exception as exc:
                print(colored("\n[*] Error: " + str(exc), "magenta"))
            else:
                if check == 1:
                    # print ("[i] Domain: "+'{:25}'.format(domain)+"\tDKIM selector: "+'{:15}'.format(selector))
                    if domain in dkim_results:
                        # append the new number to the existing array at this slot
                        dkim_results[domain].append({selector: key_size})
                    else:
                        # create a new array in this slot
                        dkim_results[domain] = [{selector: key_size}]
    return dkim_results


def check_results(dkim_results):
    for domain in dkim_results:
        for result in dkim_results[domain]:
            for selector in result:
                key_size = result[selector]

                if key_size > 1024:
                    print(
                        colored(
                            "\t[+] DKIM selector: "
                            + "{:15}".format(selector)
                            + "\tRSA key size: "
                            + str(key_size),
                            "blue",
                        )
                    )
                elif key_size == 768:
                    print(
                        colored(
                            "\t[?] DKIM selector: "
                            + "{:15}".format(selector)
                            + "\tRSA key size: "
                            + str(key_size),
                            "yellow",
                        )
                    )
                elif key_size <= 512:
                    print(
                        colored(
                            "\t[!] DKIM selector: "
                            + "{:15}".format(selector)
                            + "\tRSA key size: "
                            + str(key_size),
                            "red",
                        )
                    )
                else:
                    print(
                        "\t[i] DKIM selector: "
                        + "{:15}".format(selector)
                        + "\tRSA key size: "
                        + str(key_size)
                    )

                if args.output:
                    args.output.write(
                        domain + ";" + selector + ";" + str(key_size) + "\n"
                    )


if __name__ == "__main__":
    banner()
    args = parse_args()
    dkim_results = dict()

    dkim_selectors = load_dkim_wordlist(args.wordlist)
    print("[i] Using wordlist:", args.wordlist.name)
    print("[i] DKIM selectors in a wordlist:", str(len(dkim_selectors)) + "\n")

    if args.output:
        print("[i] Output will be saved to:", args.output.name + "\n")

    if args.domain:
        domain = args.domain
        print("[i] Scanning a single domain:", domain)
        dkim_results = scan_domain(domain)
        check_results(dkim_results)

    elif args.domains:
        domains = load_domains(args.domains)
        print("[i] Scanning multiple domains:", args.domains.name)
        print("[i] Domains in a list:", str(len(domains)))
        for domain in domains:
            print("[i] Scanning a single domain:", domain)
            dkim_results = scan_domain(domain)
            check_results(dkim_results)

    print("\n[!] Have a nice day ;)\n")
