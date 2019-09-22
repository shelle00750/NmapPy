#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os, re,commands, sys,time,serial, subprocess, socket, getpass, traceback, platform,datetime
from time import sleep
#-----------------------------------------------------------------------
from table import *
from tabulate import tabulate
from terminaltables import DoubleTable,AsciiTable
from getmac import get_mac_address

# Check if the script is running as root .
if not os.geteuid() == 0:
    sys.exit("""\033[1;91m\n[!] You must be root to run this.\n\033[1;m""")

# Exit message
exit_msg = "\033[1;91m\n[++] Shutting down...\n\033[1;m"

def main():
	
	try:
		
		def config():
			global up_interface
			up_interface = open('/opt/nmappy/tools/files/iface.txt', 'r').read()
			up_interface = up_interface.replace("\n","")
			if up_interface == "0":
				up_interface = os.popen("route | awk '/Iface/{getline; print $8}'").read()
				up_interface = up_interface.replace("\n","")

			global gateway
			gateway = open('/opt/nmappy/tools/files/gateway.txt', 'r').read()
			gateway = gateway.replace("\n","")
			if gateway == "0":
				gateway = os.popen("ip route show | grep -i 'default via'| awk '{print $3 }'").read()
				gateway = gateway.replace("\n","")

	        def home():
		        config()
		        n_mac = os.popen("ip addr | grep 'state UP' -A1 | tail -n1 | awk '{print $2}' | cut -f1  -d'/'").read() # Get network mac
		        
		        n_host = socket.gethostname()
		        
		        # or
		        
		        try:
		            n_ip = commands.getoutput("ip address show dev " + up_interface).split()
		            n_ip = n_ip[n_ip.index('inet') + 1].split('/')[0]
		        except Exception, e:
					print '[!] %s connection gateway failure' % (e)
					
			
			if os.name == "nt":
				socket_protocol = socket.IPPROTO_IP
			else:
				socket_protocol = socket.IPPROTO_ICMP

			print(""" \033[1;91m
.__   __. .___  ___.      ___      .______   .______   ____    ____  __  
|  \ |  | |   \/   |     /   \     |   _  \  |   _  \  \   \  /   / |  | 
|   \|  | |  \  /  |    /  ^  \    |  |_)  | |  |_)  |  \   \/   /  |  | 
|  . `  | |  |\/|  |   /  /_\  \   |   ___/  |   ___/    \_    _/   |  | 
|  |\   | |  |  |  |  /  _____  \  |  |      |  |          |  |     |__| 
|__| \__| |__|  |__| /__/     \__\ | _|      | _|          |__|     (__) 
                                                                         
				""")
	                print("\033[1;36m By shell.e00750..\033[1;m")
	                
			print "\n\033[1;36m[+]IP Address:\033[1;m%s"% n_ip
			print "\033[1;36m[+]MAC Address:\033[1;m%s"% n_mac.upper()
			print "\033[1;36m[+]Gateway:\033[1;m%s"% gateway
			print "\033[1;36m[+]Interface:\033[1;m%s"% up_interface
			print "\033[1;36m[+]Hostname:\033[1;m%s"% n_host
			
			print("\n\033[1;36m[1] - \033[1;mnmap, the manual scanning.\033[37m")
			print("\033[1;36m[2] - \033[1;mnmap, scan for databases.\033[37m")
			print("\033[1;36m[3] - \033[1;mnmap, scan for Trojan.\033[37m")
			print("\033[1;36m[4] - \033[1;mClose\033[37m")

			try:
			    option =(int(raw_input("\n\033[1;36m[?]option:\033[1;m")))
			except ValueError:
			    print("\033[3;91m\n[!] Error : Invalid option entered.\033[3;34m\n")
			    home()

			if option == 1:

				def mapscanm():
				    
				    print ("\033[1;36m\n[+]Type (\033[1;ma\033[1;36m) to auto scan, for manual scan type (\033[1;mip\033[1;36m) or type '\033[1;mback\033[1;36m' to \033[1;91mreturn home.\n\033[1;m")
				    target_ip = raw_input("\033[1;36m[+]type commands\033[0m\033[1;36m:\033[1;m").strip()

				    if target_ip == "a":

					gatewayip = gateway
					gtway = open('/opt/nmappy/tmp/gateway.txt', 'w')
					gtway.write(gatewayip)
					gtway.close()
				
					network_blocks = raw_input("\033[1;36m[!] Enter network blocks,example.\033[1;36m(\033[1;mip address\033[1;36m/\033[1;m24 \033[1;36mor\033[1;m 16 \033[1;36mor\033[1;m 8\033[1;36m)»\033[1;m%s\033[1;36m/\033[1;m"% gateway).strip()

					networkb = open('/opt/nmappy/tmp/network_blocks.txt', 'w')
					networkb.write(network_blocks)
					networkb.close()
				
					t_port= raw_input("\033[1;36m[!] Enter Ports for scanning,example:\033[1;36m(\033[1;m21,22,23,139,xx\033[1;36m):\033[1;m").strip()
					ports = open('/opt/nmappy/tmp/ports.txt', 'w')
					ports.write(t_port)
					ports.close()

					print("\033[1;91mMapping...\033[1;m")

					scan = os.popen("sh ./nmap").read()
					f = open('/opt/nmappy/tmp/mapgrepscan.txt','w')
					f.write(scan)
					f.close()
				
					ip_addre = os.popen("grep UP /opt/nmappy/tmp/mapgrepscan.txt | awk '{print $1}'").read()
					ports = os.popen("grep TCP /opt/nmappy/tmp/mapgrepscan.txt | awk '{print $3}'").read()
		
					table = [['IP Address','Ports']]
					table.append([ip_addre,ports])
					table = DoubleTable(table)
				
					print("\n\033[1;36m[+]Devices found on your network.¯\_(ツ)_/¯:\033[1;m")
					print (table.table).encode('utf-8')
					print "\033[1;36m[+]Scanning completed at %s\033[1;m" %(time.strftime("%I:%M:%S %p"))
					
					def target_ip():

					    print ("\033[1;36m\n[+]Type (\033[1;mback\033[1;36m) to return home,for close type (\033[1;mexit\033[1;36m) or Press '\033[1;mCtrl + C\033[1;36m' to \033[1;91mShutting down.\n\033[1;m")
					    target_ips = raw_input("\033[1;36m[+]type commands\033[0m\033[1;36m:\033[1;m").strip()

					    if target_ips == "back":
						home()

					    elif target_ips == "exit":
						print ("\n" + exit_msg)
						sleep(1)
						
					    elif target_ips == "":
						print ("\033[1;91m\n[!] Please specify a target.\033[1;m")
				    
					target_ip()
				
				    elif target_ip == "ip":

					target_ip = raw_input("\033[1;36m[!] Enter ip address for scanning,example:\033[1;36m(\033[1;m192.168.x.0\033[1;36m):\033[1;m").strip()
				    
					gatewayip = target_ip
					gtway = open('/opt/nmappy/tmp/gateway.txt', 'w')
					gtway.write(gatewayip)
					gtway.close()
				
					network_blocks = raw_input("\033[1;36m[!] Enter network blocks,example.\033[1;36m(\033[1;mip address\033[1;36m/\033[1;m24 \033[1;36mor\033[1;m 16 \033[1;36mor\033[1;m 8\033[1;36m)»\033[1;m%s\033[1;36m/\033[1;m" % target_ip).strip()
					networkb = open('/opt/nmappy/tmp/network_blocks.txt', 'w')
					networkb.write(network_blocks)
					networkb.close()
				
					t_port= raw_input("\033[1;36m[!] Enter Ports for scanning,example:\033[1;36m(\033[1;m21,22,23,139,xx\033[1;36m):\033[1;m").strip()
					ports = open('/opt/nmappy/tmp/ports.txt', 'w')
					ports.write(t_port)
					ports.close()
				    
					print("\033[1;91mMapping...\033[1;m")

					scan = os.popen("sh ./nmap").read()
					f = open('/opt/nmappy/tmp/mapgrepscan.txt','w')
					f.write(scan)
					f.close()
				
					ip_addre = os.popen("grep UP /opt/nmappy/tmp/mapgrepscan.txt | awk '{print $1}'").read()
					ports = os.popen("grep TCP /opt/nmappy/tmp/mapgrepscan.txt | awk '{print $3}'").read()
		
					table = [['IP Address','Ports']]
					table.append([ip_addre,ports])
					table = DoubleTable(table)
				
					print("\n\033[1;36m[+]Devices found on your network.¯\_(ツ)_/¯:\033[1;m")
					print (table.table).encode('utf-8')
					print "\033[1;36m[+]Scanning completed at %s\033[1;m" %(time.strftime("%I:%M:%S %p"))
					
					def target_ip():

					    print ("\033[1;36m\n[+]Type (\033[1;mback\033[1;36m) to return home,for close type (\033[1;mexit\033[1;36m) or Press '\033[1;mCtrl + C\033[1;36m' to \033[1;91mShutting down.\n\033[1;m")
					    target_ips = raw_input("\033[1;36m[+]type commands\033[0m\033[1;36m:\033[1;m").strip()

					    if target_ips == "back":
						home()

					    elif target_ips == "exit":
						print ("\n" + exit_msg)
						sleep(1)
						
					    elif target_ips == "":
						print ("\033[1;91m\n[!] Please specify a target.\033[1;m")
				    
					target_ip()
					
				    elif target_ip == "back":
					home()
				    
				    else:
					print("\033[1;91m\n[!] Error : Command not found.\033[1;m")
					mapscanm()

				mapscanm()    
			
			if option == 2:
			    
				print ("\033[1;36m\n[+]Type (\033[1;ma\033[1;36m) to auto scan, for manual scan type (\033[1;mip\033[1;36m) or type '\033[1;mback\033[1;36m' to \033[1;91mreturn home.\n\033[1;m")
			        target_ip = raw_input("\033[1;36m[+]type commands\033[0m\033[1;36m:\033[1;m").strip()
				
				if target_ip == "a":
				    
				    gatewayip = gateway
				    gtway = open('/opt/nmappy/tmp/gateway.txt', 'w')
				    gtway.write(gatewayip)
				    gtway.close()
				
				    network_blocks = raw_input("\033[1;36m[!] Enter network blocks,example.\033[1;36m(\033[1;mip address\033[1;36m/\033[1;m24 \033[1;36mor\033[1;m 16 \033[1;36mor\033[1;m 8\033[1;36m)»\033[1;m%s\033[1;36m/\033[1;m"% gateway).strip()

				    networkb = open('/opt/nmappy/tmp/network_blocks.txt', 'w')
				    networkb.write(network_blocks)
				    networkb.close()

				    print("\033[1;91mMapping...\033[1;m")

				    scan = os.popen("sh ./nmapdb").read()
				    f = open('/opt/nmappy/tmp/mapgrepscan.txt','w')
				    f.write(scan)
				    f.close()
				
				    ip_addre = os.popen("grep UP /opt/nmappy/tmp/mapgrepscan.txt | awk '{print $1}'").read()
				    ports = os.popen("grep TCP /opt/nmappy/tmp/mapgrepscan.txt | awk '{print $3}'").read()
		
				    table = [['IP Address','Ports']]
				    table.append([ip_addre,ports])
				    table = DoubleTable(table)
				
				    print("\n\033[1;36m[+]Devices found on your network.¯\_(ツ)_/¯:\033[1;m")
				    print (table.table).encode('utf-8')
				    print "\033[1;36m[+]Scanning completed at %s\033[1;m" %(time.strftime("%I:%M:%S %p"))
				    
				    def target_ip():
					
					target_parse = " --target "

					print ("\033[1;36m\n[+]Type (\033[1;mport\033[1;36m) port database info, or type (\033[1;mback\033[1;36m) to return home,for close type (\033[1;mexit\033[1;36m) or Press '\033[1;mCtrl + C\033[1;36m' to \033[1;91mShutting down.\n\033[1;m")
					target_ips = raw_input("\033[1;36m[+]type commands\033[0m\033[1;36m:\033[1;m").strip()
			        
		    
					if target_ips == "port":
					    
					
					    print ("")
					    table_datas = [
					    ["\n\n\n\nList port info\n", """
389: MySQL Enterprise Authentication LDAP & AD.

1433: Microsoft SQL Server database management system (MSSQL) server.

1434: Microsoft SQL Server database management system (MSSQL) monitor.

3050: Firebird & Interbase.

3306: MySQL Client to Server.

3351,1583: Pervasive SQL. 137-139 used for authentication.

5432: PostgreSQL.

6446: MySQL Client Any SQL to Router.

6447: MySQL Client Any SQL to Router.

6448: MySQL Client Any API calls to Router.

6449: MySQL Client ReadOnly Calls to Router.

33060: MySQL Client to Server - New X.

33061: MySQL Group Replication internal.\n"""]
					    ]
					    table = DoubleTable(table_datas)
					    print (table.table).encode('utf-8')
					    target_ip()
					    
					elif target_ips == "back":
					    home()

					elif target_ips == "exit":
					    print ("\n" + exit_msg)
					    sleep(1)
						
					elif target_ips == "":
					    print ("\033[1;91m\n[!] Please specify a target.\033[1;m")
				    
				    target_ip()
				
				elif target_ip == "ip":
				    
				    target_ip= raw_input("\033[1;36m[!] Enter ip address for scanning,example:\033[1;36m(\033[1;m192.168.x.0\033[1;36m):\033[1;m").strip()
				    #targetip = target_ip
				    
				    gatewayip = target_ip
				    gtway = open('/opt/nmappy/tmp/gateway.txt', 'w')
				    gtway.write(gatewayip)
				    gtway.close()
				
				    network_blocks = raw_input("\033[1;36m[!] Enter network blocks,example.\033[1;36m(\033[1;mip address\033[1;36m/\033[1;m24 \033[1;36mor\033[1;m 16 \033[1;36mor\033[1;m 8\033[1;36m)»\033[1;m%s\033[1;36m/\033[1;m" % target_ip).strip()
				    networkb = open('/opt/nmappy/tmp/network_blocks.txt', 'w')
				    networkb.write(network_blocks)
				    networkb.close()

				    print("\033[1;91mMapping...\033[1;m")

				    scan = os.popen("sh ./nmapdb").read()
				    f = open('/opt/nmappy/tmp/mapgrepscan.txt','w')
				    f.write(scan)
				    f.close()
				
				    ip_addre = os.popen("grep UP /opt/nmappy/tmp/mapgrepscan.txt | awk '{print $1}'").read()
				    ports = os.popen("grep TCP /opt/nmappy/tmp/mapgrepscan.txt | awk '{print $3}'").read()
		
				    table = [['IP Address','Ports']]
				    table.append([ip_addre,ports])
				    table = DoubleTable(table)
				    
				
				    print("\n\033[1;36m[+]Devices found on your network.¯\_(ツ)_/¯:\033[1;m")
				    print (table.table).encode('utf-8')
				    print "\033[1;36m[+]Scanning completed at %s\033[1;m" %(time.strftime("%I:%M:%S %p"))
				    
				    def target_ip():
					
					target_parse = " --target "

					print ("\033[1;36m\n[+]Type (\033[1;mport\033[1;36m) port database info , or type (\033[1;mback\033[1;36m) to return home,for close type (\033[1;mexit\033[1;36m) or Press '\033[1;mCtrl + C\033[1;36m' to \033[1;91mShutting down.\n\033[1;m")
					target_ips = raw_input("\033[1;36m[+]type commands\033[0m\033[1;36m:\033[1;m").strip()
			        
		    
					if target_ips == "port":
					    
					
					    print ("")
					    table_datas = [
					    ["\n\n\n\nList port info\n", """

389: MySQL Enterprise Authentication LDAP & AD.

1433: Microsoft SQL Server database management system (MSSQL) server.

1434: Microsoft SQL Server database management system (MSSQL) monitor.

3050: Firebird & Interbase.

3306: MySQL Client to Server.

3351,1583: Pervasive SQL. 137-139 used for authentication.

5432: PostgreSQL.

6446: MySQL Client Any SQL to Router.

6447: MySQL Client Any SQL to Router.

6448: MySQL Client Any API calls to Router.

6449: MySQL Client ReadOnly Calls to Router.

33060: MySQL Client to Server - New X.

33061: MySQL Group Replication internal.\n"""]
					    ]
					    table = DoubleTable(table_datas)
					    #print(table.table)
					    print (table.table).encode('utf-8')
					    target_ip()
					    
					elif target_ips == "back":
					    home()

					elif target_ips == "exit":
					    print ("\n" + exit_msg)
					    sleep(1)
					    
					elif target_ips == "":
					    print ("\033[1;91m\n[!] Please specify a target.\033[1;m")
				    
				    target_ip()
				    
				elif target_ip == "back":
					home()

				else:
				    print("\033[1;91m\n[!] Error : Command not found.\033[1;m")
				    mapscanm()
   
			if option == 3:
			    
			    
				print ("\033[1;36m\n[+]Type (\033[1;ma\033[1;36m) to auto scan, for manual scan type (\033[1;mip\033[1;36m) or type '\033[1;mback\033[1;36m' to \033[1;91mreturn home.\n\033[1;m")
			        target_ip = raw_input("\033[1;36m[+]type commands\033[0m\033[1;36m:\033[1;m").strip()
				
				if target_ip == "a":
				    
				    gatewayip = gateway
				    gtway = open('/opt/nmappy/tmp/gateway.txt', 'w')
				    gtway.write(gatewayip)
				    gtway.close()
				
				    network_blocks = raw_input("\033[1;36m[!] Enter network blocks,example.\033[1;36m(\033[1;mip address\033[1;36m/\033[1;m24 \033[1;36mor\033[1;m 16 \033[1;36mor\033[1;m 8\033[1;36m)»\033[1;m%s\033[1;36m/\033[1;m"% gateway).strip()

				    networkb = open('/opt/nmappy/tmp/network_blocks.txt', 'w')
				    networkb.write(network_blocks)
				    networkb.close()

				    print("\033[1;91mMapping...\033[1;m")

				    scan = os.popen("sh ./nmaptrojan").read()
				    f = open('/opt/nmappy/tmp/mapgrepscan.txt','w')
				    f.write(scan)
				    f.close()
				
				    ip_addre = os.popen("grep UP /opt/nmappy/tmp/mapgrepscan.txt | awk '{print $1}'").read()
				    ports = os.popen("grep TCP /opt/nmappy/tmp/mapgrepscan.txt | awk '{print $3}'").read()
		
				    table = [['IP Address','Ports']]
				    table.append([ip_addre,ports])
				    table = DoubleTable(table)
				
				    print("\n\033[1;36m[+]Devices found on your network.¯\_(ツ)_/¯:\033[1;m")
				    print (table.table).encode('utf-8')
				    print "\033[1;36m[+]Scanning completed at %s\033[1;m" %(time.strftime("%I:%M:%S %p"))
				    
				    def target_ip():
					
					#target_parse = " --target "

					print ("\033[1;36m\n[+]Type (\033[1;mport\033[1;36m) to port trojan info, or type (\033[1;mback\033[1;36m) to return home,for close type (\033[1;mexit\033[1;36m) or Press '\033[1;mCtrl + C\033[1;36m' to \033[1;91mShutting down.\n\033[1;m")
					target_ips = raw_input("\033[1;36m[+]type commands\033[0m\033[1;36m:\033[1;m").strip()
			        
					if target_ips == "port":
					    
					    print ("")
					    table = [
					    ["\n\n\n\nList Port Trojan info\n", """
21: Blade Runner, Doly Trojan, Fore, Invisible FTP, WebEx, WinCrash.

21: Blade Runner, Doly Trojan, Fore, Invisible FTP, WebEx, WinCrash.

23: Tiny Telnet Server.

25: Antigen, Email Password Sender, Haebu Coceda, Shtrilitz Stealth,Terminator, WinPC, WinSpy, Kuang2 0.17A-0.30.

31: Hackers Paradise.

80: Executor.

456: Hackers Paradise.

555: Ini-Killer, Phase Zero, Stealth Spy.

666: Satanz Backdoor

1001: Silencer, WebEx.

1011: Doly Trojan

1045: Rasmin Trojan.

1170: Psyber Stream Server Trojan.

1234: Ultors Trojan.

1243: SubSeven 1.0 - 1.8.

1245: VooDoo Doll.

1349: UDP Port > Back Ofrice DLL

1492: TP99CMP.

1600: Shivka-Burka.

1807: SpySender.

1981: ShockRave Trojan.

1999: BackDoor 1.00-1.03.

2001: Trojan Cow

2023: Ripper.

2115: Bugs.

2140: Deep Throat, The Invasor.

2801: Phineas Phucker.

3024: WinCrash.

3129: Masters Paradise Trojan.

3150: Deep Throat, The Invasor.

3700: Portal of Doom Trojan.

4092: WinCrash Trojan.

4567: File Nail 1.

4590: ICQTrojan Trojan.

4950: ICQTrojan Trojan.

5000: Bubbel.

5001: Sockets de Troie.

5321: Firehotcker Trojan.

5400: Blade Runner 0.80 Alpha.

5401: Blade Runner 0.80 Alpha.

5402: Blade Runner 0.80 Alpha.

5569: Robo-Hack Trojan.

5742: WinCrash.

6670: DeepThroat.

6671: Deep Throat Trojan.

6776: BackDoor-G, SubSeven trojans.

6939: trojan GateCrasher, Priority.

6969: GateCrasher, Priority.

7000: Remote Grab.

7300: NetMonitor.

7301: NetMonitor.

7306: NetMonitor.

7307: NetMonitor.

7308: NetMonitor.

7789: Back Door Setup, ICKiller Trojan.

8787: BackOfrice 2000.

9872: Portal of Doom Trojan.

9873: Portal of Doom v1.x Trojan.

9874: Portal of Doom v2.x Trojan.

9875: Portal of Doom v3.x Trojan.

9989: iNi-Killer Trojan.

10067: Portal of Doom v4.x Trojan.

10167: Portal of Doom v5.x Trojan.

10607: Coma 1.0.9.

11000: Senna Spy.

11223: Progenic trojan Trojan.

12223: Hack'99 KeyLogger Trojan.

12345: NetBus backdoor trojan.

12346: NetBus backdoor trojan.

12361: Whack-a-mole Trojan.

12362: Whack-a-mole Trojan.

13000: Senna Spy Trojan.

16969: Priority Trojan.

20001: Millenium Trojan.

20034: NetBus 2 Pro Trojan.

21544: GirlFriend Trojan.

22222: Prosiak Trojan.

23456: Evil FTP, Ugly FTP, WhackJob.

26274: Delta

30029: AOL Trojan.

30100: Netsphere Trojan.

30101: Netsphere Trojan.

30102: Netsphere Trojan.

30303: Sockets de Troie Trojan.

31337: TCP & UDP Port > Back Orifice.

31338: TCP & UDP Port > Back Orifice, DeepBO, NetSpy DK Trojan.

31339: NetSpy DK Trojan.

31666: BOWhack Trojan.

33333: Prosiak Trojan.

34324: BigGluck, TN, Tiny Telnet Server Trojan.

40412: BigGluck, TN, The Spy Trojan.

40421: Masters Paradise, Agent 4042 Trojan1.

40422: Masters Paradise v1.x Trojan.

40423: Masters Paradise v2.x Trojan.

40426: Masters Paradise v3.x Trojan.

47262: Delta.

50505: Sockets de Troie v2 Trojan.x.

50766: Fore, Schwindler Trojan.

53001: Remote Windows Shutdown Trojan.

54321: TCP & UDP Port > School Bus Trojan.

60000: Depp Throat Trojan.

61466: Telecommando Trojan.

65000: Devil v1.03 Trojan.\n"""]
					    ]
					    table = DoubleTable(table)
					    #print(table.table)
					    print (table.table).encode('utf-8')
					    target_ip()
					    
					elif target_ips == "back":
					    home()

					elif target_ips == "exit":
					    print ("\n" + exit_msg)
					    sleep(1)
						
					elif target_ips == "":
					    print ("\033[1;91m\n[!] Please specify a target.\033[1;m")
				    
				    target_ip()
				
				elif target_ip == "ip":
				    
				    target_ip= raw_input("\033[1;36m[!] Enter ip address for scanning,example:\033[1;36m(\033[1;m192.168.x.0\033[1;36m):\033[1;m").strip()

				    gatewayip = target_ip
				    gtway = open('/opt/nmappy/tmp/gateway.txt', 'w')
				    gtway.write(gatewayip)
				    gtway.close()
				
				    network_blocks = raw_input("\033[1;36m[!] Enter network blocks,example.\033[1;36m(\033[1;mip address\033[1;36m/\033[1;m24 \033[1;36mor\033[1;m 16 \033[1;36mor\033[1;m 8\033[1;36m)»\033[1;m%s\033[1;36m/\033[1;m" % target_ip).strip()
				    networkb = open('/opt/nmappy/tmp/network_blocks.txt', 'w')
				    networkb.write(network_blocks)
				    networkb.close()

				    print("\033[1;91mMapping...\033[1;m")

				    scan = os.popen("sh ./nmaptrojan").read()
				    f = open('/opt/nmappy/tmp/mapgrepscan.txt','w')
				    f.write(scan)
				    f.close()
				
				    ip_addre = os.popen("grep UP /opt/nmappy/tmp/mapgrepscan.txt | awk '{print $1}'").read()
				    ports = os.popen("grep TCP /opt/nmappy/tmp/mapgrepscan.txt | awk '{print $3}'").read()
		
				    table = [['IP Address','Ports']]
				    table.append([ip_addre,ports])
				    table = DoubleTable(table)
				    
				    print("\n\033[1;36m[+]Devices found on your network.¯\_(ツ)_/¯:\033[1;m")
				    print (table.table).encode('utf-8')
				    print "\033[1;36m[+]Scanning completed at %s\033[1;m" %(time.strftime("%I:%M:%S %p"))
				    
				    def target_ip():
					
					print ("\033[1;36m\n[+]Type (\033[1;mport\033[1;36m) to port trojan info , or type (\033[1;mback\033[1;36m) to return home,for close type (\033[1;mexit\033[1;36m) or Press '\033[1;mCtrl + C\033[1;36m' to \033[1;91mShutting down.\n\033[1;m")
					target_ips = raw_input("\033[1;36m[+]type commands\033[0m\033[1;36m:\033[1;m").strip()
			        		    
					if target_ips == "port":
					    
					    print ("")
					    table = [
					    ["\n\n\n\nList Port Trojan info\n", """


21: Blade Runner, Doly Trojan, Fore, Invisible FTP, WebEx, WinCrash.

21: Blade Runner, Doly Trojan, Fore, Invisible FTP, WebEx, WinCrash.

23: Tiny Telnet Server.

25: Antigen, Email Password Sender, Haebu Coceda, Shtrilitz Stealth,Terminator, WinPC, WinSpy, Kuang2 0.17A-0.30.

31: Hackers Paradise.

80: Executor.

456: Hackers Paradise.

555: Ini-Killer, Phase Zero, Stealth Spy.

666: Satanz Backdoor

1001: Silencer, WebEx.

1011: Doly Trojan

1045: Rasmin Trojan.

1170: Psyber Stream Server Trojan.

1234: Ultors Trojan.

1243: SubSeven 1.0 - 1.8.

1245: VooDoo Doll.

1349: UDP Port > Back Ofrice DLL

1492: TP99CMP.

1600: Shivka-Burka.

1807: SpySender.

1981: ShockRave Trojan.

1999: BackDoor 1.00-1.03.

2001: Trojan Cow

2023: Ripper.

2115: Bugs.

2140: Deep Throat, The Invasor.

2801: Phineas Phucker.

3024: WinCrash.

3129: Masters Paradise Trojan.

3150: Deep Throat, The Invasor.

3700: Portal of Doom Trojan.

4092: WinCrash Trojan.

4567: File Nail 1.

4590: ICQTrojan Trojan.

4950: ICQTrojan Trojan.

5000: Bubbel.

5001: Sockets de Troie.

5321: Firehotcker Trojan.

5400: Blade Runner 0.80 Alpha.

5401: Blade Runner 0.80 Alpha.

5402: Blade Runner 0.80 Alpha.

5569: Robo-Hack Trojan.

5742: WinCrash.

6670: DeepThroat.

6671: Deep Throat Trojan.

6776: BackDoor-G, SubSeven trojans.

6939: trojan GateCrasher, Priority.

6969: GateCrasher, Priority.

7000: Remote Grab.

7300: NetMonitor.

7301: NetMonitor.

7306: NetMonitor.

7307: NetMonitor.

7308: NetMonitor.

7789: Back Door Setup, ICKiller Trojan.

8787: BackOfrice 2000.

9872: Portal of Doom Trojan.

9873: Portal of Doom v1.x Trojan.

9874: Portal of Doom v2.x Trojan.

9875: Portal of Doom v3.x Trojan.

9989: iNi-Killer Trojan.

10067: Portal of Doom v4.x Trojan.

10167: Portal of Doom v5.x Trojan.

10607: Coma 1.0.9.

11000: Senna Spy.

11223: Progenic trojan Trojan.

12223: Hack'99 KeyLogger Trojan.

12345: NetBus backdoor trojan.

12346: NetBus backdoor trojan.

12361: Whack-a-mole Trojan.

12362: Whack-a-mole Trojan.

13000: Senna Spy Trojan.

16969: Priority Trojan.

20001: Millenium Trojan.

20034: NetBus 2 Pro Trojan.

21544: GirlFriend Trojan.

22222: Prosiak Trojan.

23456: Evil FTP, Ugly FTP, WhackJob.

26274: Delta

30029: AOL Trojan.

30100: Netsphere Trojan.

30101: Netsphere Trojan.

30102: Netsphere Trojan.

30303: Sockets de Troie Trojan.

31337: TCP & UDP Port > Back Orifice.

31338: TCP & UDP Port > Back Orifice, DeepBO, NetSpy DK Trojan.

31339: NetSpy DK Trojan.

31666: BOWhack Trojan.

33333: Prosiak Trojan.

34324: BigGluck, TN, Tiny Telnet Server Trojan.

40412: BigGluck, TN, The Spy Trojan.

40421: Masters Paradise, Agent 4042 Trojan1.

40422: Masters Paradise v1.x Trojan.

40423: Masters Paradise v2.x Trojan.

40426: Masters Paradise v3.x Trojan.

47262: Delta.

50505: Sockets de Troie v2 Trojan.x.

50766: Fore, Schwindler Trojan.

53001: Remote Windows Shutdown Trojan.

54321: TCP & UDP Port > School Bus Trojan.

60000: Depp Throat Trojan.

61466: Telecommando Trojan.

65000: Devil v1.03 Trojan.\n"""]
					    ]
					    table = DoubleTable(table)
					    #print(table.table)
					    print (table.table).encode('utf-8')
					    target_ip()
					    
					elif target_ips == "back":
					    home()

					elif target_ips == "exit":
					    print ("\n" + exit_msg)
					    sleep(1)
					    
					elif target_ips == "":
					    print ("\033[1;91m\n[!] Please specify a target.\033[1;m")
				    
				    target_ip()
				    
				elif target_ip == "back":
					home()

				else:
				    print("\033[1;91m\n[!] Error : Command not found.\033[1;m")
				    home()
						    
			elif option == 4:
			    print("..")
			    sleep(1)
			    print("...")
			    sleep(1)
			    sys.exit(exit_msg)
			    quit()
			
			
		home()
		config()
	
        except KeyboardInterrupt:
	    print ("\n" + exit_msg)
	    sleep(1)
        except Exception:
	    traceback.print_exc(file=sys.stdout)
	    sys.exit(0)

if __name__ == '__main__':
    main()
