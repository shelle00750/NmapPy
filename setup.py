#!/usr/bin/python
# -*- coding: utf-8 -*-

import os
import sys
from time import sleep

#---------------------------------------------------------------------------#
#                                                                           #
#        Copyright © 2019 # shell.e00750.                                   #
#                                                                           #
#---------------------------------------------------------------------------#

if not os.geteuid() == 0:
    sys.exit("""\033[1;91m\n[!] NmapPy installer must be run as root.\n\033[1;m""")

print(""" \033[1;36m

NmapPy Installer, By shell.e00750.

\033[1;m""")

def main():
    
    print("\033[1;34m\n[++] Installing NmapPy... \n\033[1;m")
    
    sleep(1)
    
    install = os.system("apt-get update && \
    pip install table && \
    pip install tabulate && \
    pip install terminaltables && \
    pip install getmac")
    
    sleep(1)
    
    install1 = os.system("""mkdir -p /opt/nmappy && \
    cp -R tools/ /opt/nmappy/ && \
    cp -R tmp/ /opt/nmappy/ && \
    cp nmappy.py /opt/nmappy/nmappy.py && \
    cp nmap /opt/nmappy/nmap && \
    cp nmapdb /opt/nmappy/nmapdb && \ 
    cp nmaptrojan /opt/nmappy/nmaptrojan && \
    cp run.sh /usr/bin/nmappy && \
    chmod +x /usr/bin/nmappy && \
    tput setaf 34; echo "NmapPy has been sucessfuly instaled. Execute 'nmappy' in your terminal." """)	
	
main()
