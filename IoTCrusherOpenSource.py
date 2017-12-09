#!/usr/bin/env python3
# -*- coding: utf-8 -*-


#-------------------------------------------------------------------------------------------------
#
#	Copyright (c) 2017, OpCode 41 Security, Inc. All rights reserved.
#
#	Redistribution and use in source and binary forms, with or without
#	modification, are permitted provided that the following conditions are
#	met:
#
#  	1. Redistributions of source code must retain the above copyright
#	   notice, this list of conditions and the following disclaimer.
#
#  	2. Redistributions in binary form must reproduce the above copyright
#     	   notice, this list of conditions and the following disclaimer in
#     	   the documentation and/or other materials provided with the
#	   distribution.
#
#  	3. Neither the name of the copyright holder, OpCode 41 Security, Inc., 
#  	   IoT Crusher, nor the names of its contributors may be used to endorse 
#  	   or promote products derived from this software without specific prior 
#  	   written permission.
#
#	THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
#	"AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
#	LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
#	A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER,
#	OPCODE 41 SECURITY, INC., OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, 
#	INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT 
#	LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
#	PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
#	LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
#	NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
#	SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#	
#-------------------------------------------------------------------------------------------------

import sys, os, time
import ipaddress, telnetlib
import argparse


# Console colors
W  = '\033[0m'  # white (normal)
R  = '\033[31m' # red
G  = '\033[32m' # green
O  = '\033[33m' # orange
B  = '\033[34m' # blue
P  = '\033[35m' # purple
C  = '\033[36m' # cyan
GR = '\033[37m' # gray


#===================================================================================================
user_pass_combos = {}
passwords_only = []
#===================================================================================================

# hajime username, password list
#http://news.softpedia.com/news/hajime-iot-worm-considerably-more-sophisticated-than-mirai-509423.shtml
user_pass_iot_hajime = {
                'admin' : ["", "admin", "password", "smcadmin"],
                'guest' : ["12345", "guest"],
                'root' : ["Zte521", "admin", "klv123", "root", "vizxv", "xc3511"],
                }

#mirai worm
#https://github.com/jgamblin/Mirai-Source-Code/blob/master/mirai/bot/scanner.c
#brickerbot uses mirai
#https://security.radware.com/ddos-threats-attacks/brickerbot-pdos-back-with-vengeance/
user_pass_mirai_worm = {
                '666666' : ["666666"],
                '888888' : ["888888"],
                'Administrator' : ["admin"],
                'admin1' : ["password"],
                'admin' : ["", "1111", "1111111", "1234", "1234", "12345", "123456", "54321", "7ujMko0admin", "admin", "admin1234", "meinsm", "pass", "password", "smcadmin"],
                'administrator' : ["1234"],
                'guest' : ["12345", "12345", "guest"],
                'mother' : ["fucker"],
                'root' : ["", "00000000", "1111", "1234", "12345", "123456", "54321", "666666", "7ujMko0admin", "7ujMko0vizxv", "888888", "Zte521", "admin", "anko", "default", "dreambox", "hi3518", "ikwb", "juantech", "jvbzd", "klv123", "klv1234", "pass", "password", "realtek", "root", "system", "user", "vizxv", "xc3511", "xmhdipc", "zlxx."],
                'service' : ["service"],
                'supervisor' : ["supervisor"],
                'support' : ["support"],
                'tech' : ["tech"],
                'ubnt' : ["ubnt"],
                'user' : ["user"],
                }



#IoT Password list taken from here:
# https://github.com/robertdavidgraham/telnetlogger/blob/master/passwords.txt
user_pass_mirai_worm_plus = {
                '666666' : ["666666"],
                '888888' : ["888888"],
                'Administrator' : ["meinsm"],
                '\x04' : ["\x01\x1f"],
                'admin' : ["1111", "1111111", "1234", "12345", "123456", "4321", "54321", "7ujMko0admin", "Administrator", "D-Link", "VTech", "admin", "admin1234", "adminr", "changeme", "cisco", "comcast", "default", "guest", "login", "manager", "meinsm", "netgear", "pass", "password", "pi", "raspberry", "root", "smcadmin", "support", "telnet", "ubnt", "user", "vagrant"],
                'admin1' : ["password"],
                'administrator' : ["1234"],
                'cisco' : ["admin", "cisco", "guest", "login", "netgear", "root", "support", "user"],
                'guest' : ["1234", "12345", "123456", "Administrator", "D-Link", "VTech", "admin", "changeme", "cisco", "comcast", "default", "guest", "login", "manager", "netgear", "password", "pi", "raspberry", "root", "support", "telnet", "ubnt", "user", "vagrant"],
                'login' : ["1234", "123456", "Administrator", "D-Link", "VTech", "admin", "changeme", "cisco", "comcast", "default", "guest", "login", "manager", "netgear", "password", "pi", "raspberry", "root", "support", "telnet", "ubnt", "user", "vagrant"],
                'mother' : ["fucker"],
                'netgear' : ["1234", "123456", "Administrator", "D-Link", "VTech", "admin", "changeme", "cisco", "comcast", "default", "guest", "login", "manager", "netgear", "password", "pi", "raspberry", "root", "support", "telnet", "ubnt", "user", "vagrant"],
                'root' : ["00000000", "1001chin", "1111", "1234", "12345", "123456", "54321", "5up", "666666", "7ujMko0admin", "7ujMko0vizxv", "888888", "Administrator", "D-Link", "GM8182", "VTech", "Zte521", "admin", "anko", "changeme", "cisco", "comcast", "default", "dreambox", "guest", "hi3518", "ikwb", "juantech", "jvbzd", "klv123", "klv1234", "login", "manager", "netgear", "pass", "password", "pi", "raspberry", "realtek", "root", "support", "system", "telnet", "toor", "ubnt", "user", "vagrant", "vizxv", "xc3511", "xmhdipc", "zlxx."],
                'service' : ["service"],
                'sh' : ["/bin/busybox\x20MIRAI"],
                'shell' : ["enable"],
                'supervisor' : ["supervisor"],
                'support' : ["1234", "123456", "Administrator", "D-Link", "VTech", "admin", "changeme", "cisco", "comcast", "default", "guest", "login", "manager", "netgear", "password", "pi", "raspberry", "root", "support", "telnet", "ubnt", "user", "vagrant"],
                'tech' : ["tech"],
                'ubnt' : ["ubnt"],
                'user' : ["1234", "123456", "Administrator", "D-Link", "VTech", "admin", "changeme", "cisco", "comcast", "default", "guest", "login", "manager", "netgear", "password", "pi", "raspberry", "root", "support", "telnet", "ubnt", "user", "vagrant"],
                }



# IoT pastebin list
# See: https://arstechnica.com/information-technology/2017/08/leak-of-1700-valid-passwords-could-make-the-iot-mess-much-worse/
user_pass_iot_pastebin = {
                'Administrator' : [""],
                'PlcmSpIp' : ["PlcmSpIp"],
                'adm' : [""],
                'admin' : ["", "1111", "11111111", "1234", "123456", "1234567890", "7ujMko0admin", "7ujMko0vizxv", "AitbISP4eCiG", "P@55w0rd!", "admin", "admin117.35.97.74", "admin123", "admin1234", "administrator", "adslroot", "atlantis", "cisco", "default", "epicrouter", "fliradmin", "jvc", "meinsma", "michaelangelo", "my_DEMARC", "oelinux123", "pass", "password", "service", "smcadmin", "support", "switch", "tech", "ubnt", "wbox"],
                'alpine' : ["alpine"],
                'daemon' : [""],
                'default' : ["", "antslq", "default", "password"],
                'guest' : ["", "1111", "12345", "123456", "guest", "xc3511"],
                'mg3500' : ["merlin"],
                'mother' : ["fucker"],
                'operator' : ["operator"],
                'oracle' : ["oracle"],
                'root' : ["", "000000", "1111", "1234", "12345", "123456", "1234567890", "1234qwer", "123qwe", "1q2w3e4r5", "3ep5w2u", "54321", "666666", "7ujMko0admin", "7ujMko0vizxv", "888888", "GMB182", "LSiuY7pOmZG2s", "PASSWORD", "ROOT500", "Serv4EMC", "Zte521", "abc123", "admin", "admin1234", "ahetzip8", "alpine", "anko", "antslq", "ascend", "attack", "avtech", "b120root", "bananapi", "blender", "calvin", "changeme", "cms500", "comcom", "coolphoenix579", "davox", "default", "dreambox", "fivranne", "ggdaseuaimhrke", "hi3518", "iDirect", "ikwb", "ikwd", "jauntech", "juantech", "jvbzd", "klv123", "klv1234", "maxided", "oelinux123", "openssh", "openvpnas", "orion99", "pa55w0rd", "pass", "password", "realtek", "root", "tini", "tslinux", "user", "vizxv", "xc3511", "xmhdipc", "zlxx.", "zte9x15"],
                'supervisor' : ["supervisor", "zyad1234"],
                'support' : ["123", "1234", "12345", "123456", "admin", "login", "support", "zlxx."],
                'tech' : ["tech"],
                'telnet' : ["telnet"],
                'ubnt' : ["ubnt"],
                'user' : ["", "123456", "user"],
                }



# https://github.com/eset/malware-research/blob/master/moose/targeted-vendors/default-credentials-list.txt
user_pass_iot_vendor_malware = {
                '!root' : [""],
                '11111' : ["x-admin"],
                '1234' : ["1234"],
                'ADMINISTRATOR' : ["ADMINISTRATOR"],
                'ADMN' : ["admn"],
                'ADSL' : ["expert03"],
                'ADVMAIL' : ["HP", "HPOFFICE DATA"],
                'Admin' : ["123456"],
                'Administrator' : ["", "admin", "changeme", "ganteng", "ggdaseuaimhrke", "password", "smcadmin"],
                'Alphanetworks' : ["wrgg15_di524", "wrgn49_dlob_dir300b5"],
                'Any' : ["12345"],
                'CISCO15' : ["otbu+1"],
                'CSG' : ["SESAME"],
                'D-Link' : ["D-Link"],
                'FIELD' : ["HPONLY", "HPP187 SYS", "HPWORD PUB", "LOTUS", "MANAGER", "MGR", "SERVICE", "SUPPORT"],
                'Factory' : ["56789"],
                'GEN1' : ["gen1"],
                'GEN2' : ["gen2"],
                'HELLO' : ["FIELD.SUPPORT", "MANAGER.SYS", "MGR.SYS", "OP.OPERATOR"],
                'HTTP' : ["HTTP"],
                'IntraStack' : ["Asante"],
                'IntraSwitch' : ["Asante"],
                'MAIL' : ["HPOFFICE", "MAIL", "MPE", "REMOTE", "TELESUP"],
                'MANAGER' : ["COGNOS", "HPOFFICE", "ITF3000", "SECURITY", "SYS", "TCH", "TELESUP"],
                'MD110' : ["help"],
                'MGR' : ["CAROLIAN", "CCC", "CNAS", "COGNOS", "CONV", "HPDESK", "HPOFFICE", "HPONLY", "HPP187", "HPP189", "HPP196", "INTX3", "ITF3000", "NETBASE", "REGO", "RJE", "ROBELLE", "SECURITY", "SYS", "TELESUP", "VESOFT", "WORD", "XLSERVER"],
                'MICRO' : ["RSX"],
                'Manager' : ["", "Admin"],
                'NAU' : ["NAU"],
                'NICONEX' : ["NICONEX"],
                'OPERATOR' : ["COGNOS", "DISC", "SUPPORT", "SYS", "SYSTEM"],
                'PCUSER' : ["SYS"],
                'PRODDTA' : ["PRODDTA"],
                'RMUser1' : ["password"],
                'RSBCMON' : ["SYS"],
                'SPOOLMAN' : ["HPOFFICE"],
                'SSA' : ["SSA"],
                'SYSADM' : ["sysadm"],
                'SYSDBA' : ["masterkey"],
                'Service' : ["5678"],
                'TMAR#HWMT8007079' : [""],
                'User' : [""],
                'WP' : ["HPOFFICE"],
                'abc' : ["cascade"],
                'adm' : [""],
                'admin2' : ["changeme"],
                'admin' : ["", "0", "123", "1234", "1234admin", "2222", "3477", "3ascotel", "9999", "Admin", "BRIDGE", "Intel", "NetCache", "NetICs", "OCS", "P@55w0rd!", "PASSWORD", "SMDR", "SUPER", "Symbol", "TANDBERG", "_Cisco", "access", "admin", "adminttd", "adslolitec", "adslroot", "adtran", "asante", "ascend", "atc123", "atlantis", "backdoor", "barricade", "bintec", "comcomcom", "default", "enter", "epicrouter", "extendnet", "hello", "help", "ironport", "isee", "letmein", "leviton", "michelangelo", "microbusiness", "mu", "my_DEMARC", "netadmin", "noway", "passwort", "pento", "pfsense", "private", "public", "rmnetlm", "root", "setup", "sitecom", "smcadmin", "speedxess", "switch", "sysAdmin", "system"],
                'adminstat' : ["OCS"],
                'adminstrator' : ["changeme"],
                'adminttd' : ["adminttd"],
                'adminuser' : ["OCS"],
                'adminview' : ["OCS"],
                'ami' : [""],
                'apc' : ["apc"],
                'bbsd-client' : ["NULL", "changeme2"],
                'cablecom' : ["router"],
                'ccrusr' : ["ccrusr"],
                'cellit' : ["cellit"],
                'cisco' : ["", "cisco"],
                'citel' : ["citel"],
                'corecess' : ["corecess"],
                'craft' : [""],
                'cusadmin' : ["highspeed"],
                'dadmin' : ["dadmin01"],
                'davox' : ["davox"],
                'debug' : ["d.e.b.u.g", "synnet"],
                'deskalt' : ["password"],
                'deskman' : ["changeme"],
                'desknorm' : ["password"],
                'deskres' : ["password"],
                'diag' : ["danger", "switch"],
                'disttech' : ["4tas"],
                'draytek' : ["1234"],
                'echo' : ["User"],
                'guest' : ["", "User", "guest"],
                'helpdesk' : ["OCS"],
                'hsa' : ["hsadb"],
                'iclock' : ["timely"],
                'images' : ["images"],
                'install' : ["secret"],
                'installer' : ["installer"],
                'intermec' : ["intermec"],
                'l2' : ["l2"],
                'l3' : ["l3"],
                'login' : ["admin", "password"],
                'm1122' : ["m1122"],
                'maint' : ["maint", "ntacdmax"],
                'manage !manage' : [""],
                'manager' : ["friend", "manager"],
                'manuf' : ["xxyyzz"],
                'mediator' : ["mediator"],
                'mlusr' : ["mlusr"],
                'monitor' : ["monitor"],
                'netopia' : ["netopia"],
                'netrangr' : ["attack"],
                'netscreen' : ["netscreen"],
                'nokai' : ["nokai"],
                'nokia' : ["nokia"],
                'operator' : ["", "1234", "operator"],
                'patrol' : ["patrol"],
                'public' : [""],
                'radware' : ["radware"],
                'readonly' : ["lucenttech2"],
                'readwrite' : ["lucenttech1"],
                'recovery' : ["recovery"],
                'replicator' : ["replicator"],
                'ro' : ["ro"],
                'root' : ["", "1234", "12345", "3ep5w2u", "Admin", "Mau'dib", "admin", "admin_1", "ascend", "attack", "blender", "davox", "default", "fivranne", "ggdaseuaimhrke", "iDirect", "pass", "password", "root", "tini", "tslinux"],
                'rw' : ["rw"],
                'rwa' : ["rwa"],
                'scmadmin' : ["scmchangeme"],
                'scout' : ["scout"],
                'secret' : ["secret"],
                'secure' : ["secure"],
                'security' : ["security"],
                'service' : ["smile"],
                'setup' : ["changeme", "setup"],
                'smc' : ["smcadmin"],
                'storwatch' : ["specialist"],
                'stratacom' : ["stratauser"],
                'super.super' : ["", "master"],
                'super' : ["super", "surt"],
                'superman' : ["talent"],
                'superuser' : ["", "123456", "admin"],
                'supervisor' : ["supervisor"],
                'support' : ["support"],
                'sysadm' : ["Admin", "anicust"],
                'sysadmin' : ["PASS", "password"],
                'target' : ["password"],
                'teacher' : ["password"],
                'tech' : ["", "tech"],
                'telecom' : ["telecom"],
                'tellabs' : ["tellabs#1"],
                'temp1' : ["password"],
                'tiger' : ["tiger123"],
                'topicalt' : ["password"],
                'topicnorm' : ["password"],
                'topicres' : ["password"],
                'user' : ["password"],
                'vcr' : ["NetVCR"],
                'vt100' : ["public"],
                'wlse' : ["wlsedb"],
                'write' : ["private"],
                'xd' : ["xd"],
                }


#===================================================================================================
#===================================================================================================


#--------------------------------------------------------------------------
def IoTcrusherBruteForceParms():
#--------------------------------------------------------------------------


    cmdline = argparse.ArgumentParser(description='IoT Crusher BruteForcer by OpCode41 Security, Inc.')

    cmdline.add_argument('-networkAddresses', required=True, help='Enter Network IP Addressing, ex.: 192.168.1.0/24 192.168.1.100/32')
    cmdline.add_argument('-credList', required=True, default='ALL', choices=['ALL', 'hajime', 'mirai', 'mirai+', 'pastebin', 'vendors'], nargs='+', help='Select Default Credentials to Test')
    cmdline.add_argument('-checkBanner', default='False', choices=['True', 'False'], help='Check "Unauthorized" Banner (True) or Scan All Devices (False)')

    results = vars(cmdline.parse_args())

    return results


#-----------------------------------------------------------------
def build_testing_usernames_passwords(credLists):
#-----------------------------------------------------------------

    global user_pass_combos
    global passwords_only

    print("* Starting to build combos of user credentials!")

    if 'ALL' in credLists:

        user_pass_combos = combine_two_dict_w_arrays(user_pass_iot_hajime, user_pass_combos)
        user_pass_combos = combine_two_dict_w_arrays(user_pass_mirai_worm, user_pass_combos)
        user_pass_combos = combine_two_dict_w_arrays(user_pass_mirai_worm_plus, user_pass_combos)
        user_pass_combos = combine_two_dict_w_arrays(user_pass_iot_pastebin, user_pass_combos)
        user_pass_combos = combine_two_dict_w_arrays(user_pass_iot_vendor_malware, user_pass_combos)

    else:

        for credList in credLists:
        
            if credList == 'hajime':
                user_pass_combos = combine_two_dict_w_arrays(user_pass_iot_hajime, user_pass_combos)

            elif credList == 'mirai':
                user_pass_combos = combine_two_dict_w_arrays(user_pass_mirai_worm, user_pass_combos)

            elif credList == 'mirai+':
                user_pass_combos = combine_two_dict_w_arrays(user_pass_mirai_worm_plus, user_pass_combos)

            elif credList == 'pastebin':
                user_pass_combos = combine_two_dict_w_arrays(user_pass_iot_pastebin, user_pass_combos)

            elif credList == 'vendors':
                user_pass_combos = combine_two_dict_w_arrays(user_pass_iot_vendor_malware, user_pass_combos)


    passwords_only = create_passwords_only(user_pass_combos)

    print("* Finished building combos of user credentials!")


#--------------------------------------------------------------------------
def combine_two_dict_w_arrays(dict_to_merge, combined_dict):
#--------------------------------------------------------------------------
    
    #get key
    for key in dict_to_merge:
        #check if key in combined dictionary
        if key in combined_dict.keys():
            #if it is now we check and add key values to cmobined key array
            new_password_array = []
            for array_vals in dict_to_merge[key]:
                #loop through combined dictionary for merging key
                dont_add_value = False
                for return_val in combined_dict[key]:
                    #add exiting values back into array
                    if not return_val in new_password_array:
                        new_password_array.append(return_val)

                    # this says if the passsword is in the 
                    # combined array don't add it
                    if array_vals == return_val:
                        dont_add_value = True

                                        
                if not dont_add_value:
                    new_password_array.append(array_vals)
                    
            combined_dict[key] = new_password_array
            
        else:
            # we just add the whole thing if the key isn't in there already
            combined_dict[key] = dict_to_merge[key]
    
    return combined_dict


#-----------------------------------------------------------
def create_passwords_only(user_pass_combos):
#-----------------------------------------------------------

    passwords_only = []
    for username in user_pass_combos:
        for pwd in user_pass_combos[username]:
            if not pwd in passwords_only:
                passwords_only.append(pwd)

    passwords_only.sort()

    return passwords_only



#-----------------------------------------------------------------
def load_ip_addresses(cmdline_text):
#-----------------------------------------------------------------

    print("* Parsing network addresses supplied!")
    ipaddresses = []

    try:
        net4 = ipaddress.ip_network(cmdline_text)
        
        # hosts() has a weird bug that you cannot mask a single IP address
        if "/32" in cmdline_text:
            ipaddresses.append(cmdline_text.replace("/32","").strip())
        else:
        
            for x in net4.hosts():
                ipaddresses.append(x)

        print("* Finished parsing network addresses supplied!")
        return ipaddresses

    except Exception as e:

        print(R + "Looks like there was an error with the supplied network address format." + W)
        print(R + "Here's the system generated error message:" + W)
        print(R + str(e)+ W)
        print("Exiting Program...")
        sys.exit()




#===================================================================================================
#    telnet brute forcing routines
#===================================================================================================

#-----------------------------------------------------------------
def attack_telnet(ipaddress, port, respect_banner):
#-----------------------------------------------------------------


    try:
        tn = telnetlib.Telnet(str(ipaddress), int(port), 5)

        try:
            timeout = time.time() + 30   # 30 seconds from now

            initial_connection_output = ""
            continue_flag = True
            while continue_flag:
                output_temp = tn.read_very_eager().decode('utf-8', 'ignore')
                initial_connection_output = initial_connection_output + output_temp.strip()

                # we didn't get back enough data to make a decision
                if telnet_loginPrompt_check(initial_connection_output):
                   continue_flag = False
                
                # there is a problem so we do not want to continue testing
                if time.time() > timeout:
                    tn.close()
                    return

            # check for unauthorized banner 
            if respect_banner:
                #    2. will we test the device (authorized check)?
                if telnet_unauthorized_check(initial_connection_output):
                    tn.close()
                    return
                
            #    3. if so, are we logged in automatically?
            if telnet_cmd_prompt_check(initial_connection_output):
                # logged in as root???
                if telnet_cmd_prompt_root_check(initial_connection_output):
                    print_vuln_device_default(ipaddress, port, "Logged into device as ROOT! without u/p upon connection!!!")
                else:
                    print_vuln_device_default(ipaddress, port, "Logged into device without u/p upon connection!!!")

                tn.close()
                return
                    
            #    4. are we looking at a password prompt?
            if telnet_pwdPrompt_check(initial_connection_output):
                #close existing connection object
                tn.close()
                #run password attack routine
                attack_telnet_pwdonly(ipaddress, port)
                
            else:
                # double check we're looking at a username prompt!
                #    5. are we looking at a username prompt?
                if telnet_unamePrompt_check(initial_connection_output):

                    #    5a. if we enter the wrong username do we get back a password or username prompt?
                    tn.write(str(str("thisisnotarealusername").strip()).encode('ascii'))
                    tn.write(str("\r\n").encode('ascii'))

                    timeout = time.time() + 30   # 30 seconds from now

                    username_prompt_check_output = ""
                    continue_flag = True

                    while continue_flag:
                        output_temp = tn.read_very_eager().decode('utf-8', 'ignore')
                        username_prompt_check_output = username_prompt_check_output + output_temp.strip()

                        # we didn't get back enough data to make a decision
                        if telnet_loginPrompt_check(username_prompt_check_output):
                            continue_flag = False

                
                        # there is a problem so we do not want to continue testing
                        if time.time() > timeout:
                            tn.close()
                            return
                    
                    # we found a username prompt instead of a password prompt
                    if telnet_unamePrompt_check(username_prompt_check_output):
                        tn.close()
                        attack_telnet_uname_logic(ipaddress, port)

                    else:
                        #standard u/p brute forcing attack sequence
                        tn.close()
                        attack_telnet_userpass(ipaddress, port)


                # we didn't pass any check or call any routine
                # no idea about what's going on so we will not test device
                # could be too many connected devices... Device account lockout or something else
                else:
                    tn.close()
                    return

        # there was some error along the way!
        except Exception as e:
            tn.close()
            return

    # telnet connection failed
    except Exception as e:
        pass
    


#-----------------------------------------------------------------
def attack_telnet_userpass(ipaddress, port):
#-----------------------------------------------------------------
    
    # this is the standard U/P attack that people think about. 

    for username in user_pass_combos:
        for pwd in user_pass_combos[username]:

            try:
                tn = telnetlib.Telnet(str(ipaddress), int(port), 5)

                #this try is for all the processing outside the initial connection
                #if we fail on the processing we try the next combo
                #if we fail on the connection we leave and don't try any more combos
                try:
                    timeout = time.time() + 30   # 30 seconds from now

                    username_prompt = ""
                    continue_flag = True
                    while continue_flag:
                        output_temp = tn.read_very_eager().decode('utf-8', 'ignore')
                        username_prompt = username_prompt + output_temp.strip()

                        # we didn't get back enough data to make a decision
                        if telnet_loginPrompt_check(username_prompt):
                            continue_flag = False
                
                        # there is a problem so we do not want to continue testing
                        if time.time() > timeout:
                            tn.close()
                            return

                    #### Send UserName!
                    tn.write(str(str(username).strip()).encode('ascii'))
                    tn.write(str("\r\n").encode('ascii'))

                    #### Now we wait for password prompt
                    password_prompt = ""
                    continue_flag = True
                    while continue_flag:
                        output_temp = tn.read_very_eager().decode('utf-8', 'ignore')
                        password_prompt = password_prompt + output_temp.strip()

                        # we didn't get back enough data to make a decision
                        if telnet_pwdPrompt_check(password_prompt):
                            continue_flag = False
                
                        # there is a problem so we do not want to continue testing
                        if time.time() > timeout:
                            tn.close()
                            return


                    #### send password!!!
                    #if password isn't blank we send it, otherwise we just hit enter
                    if str(pwd).strip():
                        tn.write(str(str(pwd).strip()).encode('ascii'))
                    tn.write(str("\r\n").encode('ascii'))


                    #### Do we have a shell
                    shell_prompt = ""
                    continue_flag = True
                    while continue_flag:
                        output_temp = tn.read_very_eager().decode('utf-8', 'ignore')
                        shell_prompt = shell_prompt + output_temp.strip()

                        # we need to see how the device responds
                        # got back a username prompt; time to exit
                        if telnet_loginPrompt_check(shell_prompt):
                            continue_flag = False
                            tn.close()

                        # weird that we would get back a password prompt here but
                        # we're still not logged in - so invalid creds; time to exit               
                        elif telnet_pwdPrompt_check(shell_prompt):
                            continue_flag = False
                            tn.close()

                        # we might actually find we had valid credentials
                        elif telnet_cmd_prompt_check(shell_prompt):
                            tn.write(str(str("exit").strip()).encode('ascii'))
                            tn.write(str("\r\n").encode('ascii'))
                        
                            # we close the connection in case the exit does not (for whatever reason)
                            try:
                                tn.close()
                            except:
                                pass

                            #are we root????
                            # report the vulnerable device
                            if telnet_cmd_prompt_root_check(shell_prompt):
                                print_vuln_device_info_root(ipaddress, port, username, pwd )
                            else:
                                print_vuln_device_info(ipaddress, port, username, pwd )

                            #print the shell! :)
                            print(shell_prompt)
                            
                            #flag is unnecessary as we will return... ;)
                            continue_flag = False
                        
                            # here we need option to check all combos or just first one we hit
                            return
                            #break (if future flag says test all combos)

                        # there is a problem so we do not want to continue testing
                        if time.time() > timeout:
                            tn.close()
                            break

                # this is a generic processing routine catch and ignore exceptiom
                except Exception as e:
                #we've run into some problem so we close connection
                # and we move onto next combination
                    tn.close()
                    pass


            except Exception as e:
                #we've run into some problem so we close connection
                # and we move onto next host
                try:             
                    tn.close()
                except:
                    pass
                return




#-----------------------------------------------------------------
def attack_telnet_uname_logic(ipaddress, port):
#-----------------------------------------------------------------

    # we need to check all usernames first before trying the U/P combos
    for username in user_pass_combos:

        try:
            tn = telnetlib.Telnet(str(ipaddress), int(port), 5)

            #this try is for all the processing outside the initial connection
            #if we fail on the processing we try the next combo
            #if we fail on the connection we leave and don't try any more combos
            try:
                timeout = time.time() + 30   # 30 seconds from now

                username_prompt = ""
                continue_flag = True
                while continue_flag:
                    output_temp = tn.read_very_eager().decode('utf-8', 'ignore')
                    username_prompt = username_prompt + str(output_temp).strip()

                    # we didn't get back enough data to make a decision
                    if telnet_loginPrompt_check(username_prompt):
                        continue_flag = False
                
                    # there is a problem so we do not want to continue testing
                    if time.time() > timeout:
                        tn.close()
                        return

                #### Send UserName!
                tn.write(str(str(username).strip()).encode('ascii'))
                tn.write(str("\r\n").encode('ascii'))

                #### Now we wait for password prompt
                password_flag = False
                    
                password_prompt = ""
                continue_flag = True
                while continue_flag:
                    output_temp = tn.read_very_eager().decode('utf-8', 'ignore')
                    password_prompt = password_prompt + str(output_temp).strip()

                    # we didn't get back enough data to make a decision
                    if telnet_loginPrompt_check(password_prompt):
                        continue_flag = False

                        
                    elif telnet_pwdPrompt_check(password_prompt):
                        tn.close()
                        continue_flag = False
                        password_flag = True
                
                    # there is a problem so we do not want to continue testing
                    if time.time() > timeout:
                        tn.close()
                        return

                #since we have a password prompt
                # now test passwords for username
                
                # we should disconnect and reconnect using the username so we get a clean loop
                
                if password_flag:
                    for pwd in user_pass_combos[username]:

                        try:
                            timeout = time.time() + 30   # 30 seconds from now

                            username_prompt = ""
                            continue_flag = True
                            while continue_flag:
                                output_temp = tn.read_very_eager().decode('utf-8', 'ignore')
                                username_prompt = username_prompt + str(output_temp).strip()

                                # we didn't get back enough data to make a decision
                                if telnet_loginPrompt_check(username_prompt):
                                    continue_flag = False
                
                                # there is a problem so we do not want to continue testing
                                if time.time() > timeout:
                                    tn.close()
                                    return


                            #### Send UserName!
                            tn.write(str(str(username).strip()).encode('ascii'))
                            tn.write(str("\r\n").encode('ascii'))


                            #### Now we wait for password prompt
                            password_prompt = ""
                            continue_flag = True
                            while continue_flag:
                                output_temp = tn.read_very_eager().decode('utf-8', 'ignore')
                                password_prompt = password_prompt + str(output_temp).strip()

                                # we didn't get back enough data to make a decision
                                # this shouldn't happen ????
                                if telnet_loginPrompt_check(password_prompt):
                                    continue_flag = False

                        
                                elif telnet_pwdPrompt_check(password_prompt):
                                    continue_flag = False
                
                                # there is a problem so we do not want to continue testing
                                if time.time() > timeout:
                                    tn.close()
                                    return


                            #### send password!!!
                            #if password isn't blank we send it, otherwise we just hit enter
                            if str(pwd).strip():
                                tn.write(str(str(pwd).strip()).encode('ascii'))
                            tn.write(str("\r\n").encode('ascii'))


                            #### Do we have a shell
                            shell_prompt = ""
                            continue_flag = True
                            while continue_flag:
                                output_temp = tn.read_very_eager().decode('utf-8', 'ignore')
                                shell_prompt = shell_prompt + str(output_temp).strip()

                                # we need to see how the device responds
                                # got back a username prompt; time to exit
                                if telnet_loginPrompt_check(shell_prompt):                                    
                                    continue_flag = False
                                    tn.close()

                                # weird that we would get back a password prompt here but
                                # we're still not logged in - so invalid creds; time to exit               
                                elif telnet_pwdPrompt_check(shell_prompt):
                                    continue_flag = False
                                    tn.close()

                                # we might actually find we had valid credentials
                                elif telnet_cmd_prompt_check(shell_prompt):
                                    tn.write(str(str("exit").strip()).encode('ascii'))
                                    tn.write(str("\r\n").encode('ascii'))
                        
                                    # we close the connection in case the exit does not (for whatever reason)
                                    try:
                                        tn.close()
                                    except:
                                        pass
                        
                                    #are we root????
                                    # report the vulnerable device
                                    if telnet_cmd_prompt_root_check(shell_prompt):
                                        print_vuln_device_info_root(ipaddress, port, username, pwd )
                                    else:
                                        print_vuln_device_info(ipaddress, port, username, pwd )

                                    #print the shell! :)
                                    print(shell_prompt)

                                    #flag is unnecessary as we will return... ;)
                                    continue_flag = False
                        
                                    # here we need option to check all combos or just first one we hit
                                    return
                                    #break (if future flag says test all combos)

                                # there is a problem so we do not want to continue testing
                                if time.time() > timeout:
                                    tn.close()
                                    break


                        # this is a generic processing routine catch and ignore exceptiom
                        except Exception as e:
                            #we've run into some problem so we close connection
                            # and we move onto next combination
                            tn.close()
                            pass


        

            # this is a generic processing routine catch and ignore exceptiom
            except Exception as e:
                #we've run into some problem so we close connection
                # and we move onto next combination
                tn.close()
                pass


        except Exception as e:
            #we've run into some problem so we close connection
            # and we move onto next host
            try:             
                tn.close()
            except:
                pass
            return
        
        
#-----------------------------------------------------------------
def attack_telnet_pwdonly(ipaddress, port):
#-----------------------------------------------------------------

    # this telnet only requires a password without a username
    for pwd in passwords_only:

        try:
            tn = telnetlib.Telnet(str(ipaddress), int(port), 5)

            #this try is for all the processing outside the initial connection
            #if we fail on the processing we try the next combo
            #if we fail on the connection we leave and don't try any more combos
            try:
                timeout = time.time() + 30   # 30 seconds from now
        
                password_prompt = ""
                continue_flag = True
                while continue_flag:
                    output_temp = tn.read_very_eager().decode('utf-8', 'ignore')
                    password_prompt = password_prompt + output_temp.strip()

                    # we didn't get back enough data to make a decision
                    if telnet_pwdPrompt_check(password_prompt):
                        continue_flag = False
                
                    # there is a problem so we do not want to continue testing
                    if time.time() > timeout:
                        tn.close()
                        return

                #### send password!!!
                #if password isn't blank we send it, otherwise we just hit enter
                if str(pwd).strip():
                    tn.write(str(str(pwd).strip()).encode('ascii'))
                tn.write(str("\r\n").encode('ascii'))


                #### Do we have a shell
                shell_prompt = ""
                continue_flag = True
                while continue_flag:
                    output_temp = tn.read_very_eager().decode('utf-8', 'ignore')
                    shell_prompt = shell_prompt + output_temp.strip()

                    # weird that we would get back a username prompt here but
                    # we're still not logged in - so invalid creds; time to exit               
                    if telnet_loginPrompt_check(shell_prompt):
                        continue_flag = False
                        tn.close()

                    # we need to see how the device responds
                    # got back a password prompt; time to exit
                    elif telnet_pwdPrompt_check(shell_prompt):
                        continue_flag = False
                        tn.close()

                    # we might actually find we had valid credentials
                    elif telnet_cmd_prompt_check(shell_prompt):
                        tn.write(str(str("exit").strip()).encode('ascii'))
                        tn.write(str("\r\n").encode('ascii'))
                        
                        # we close the connection in case the exit does not (for whatever reason)
                        try:
                            tn.close()
                        except:
                            pass
                        
                        #are we root????
                        # report the vulnerable device
                        if telnet_cmd_prompt_root_check(shell_prompt):
                            print_vuln_device_info_root(ipaddress, port, "(none)", pwd )
                        else:
                            print_vuln_device_info(ipaddress, port, "(none)", pwd )


                        #print the shell! :)
                        print(shell_prompt)

                        #flag is unnecessary as we will return... ;)
                        continue_flag = False
                        
                        # here we need option to check all combos or just first one we hit
                        return
                        #break (if future flag says test all combos)

                        # there is a problem so we do not want to continue testing
                    if time.time() > timeout:
                        tn.close()
                        break
        

            # this is a generic processing routine catch and ignore exceptiom
            except Exception as e:
                #we've run into some problem so we close connection
                # and we move onto next combination
                tn.close()
                pass


        except Exception as e:
            #we've run into some problem so we close connection
            # and we move onto next host
            try:             
                tn.close()
            except:
                pass
            return





#-----------------------------------------------------------------
def telnet_loginPrompt_check(textCheck):
#-----------------------------------------------------------------

    if ":" in str(textCheck).lower()[-4:]:
        return True

    return False


#-----------------------------------------------------------------
def telnet_cmd_prompt_check(textCheck):
#-----------------------------------------------------------------

    if ">" in str(textCheck).lower()[-4:]:
        return True
    elif "#" in str(textCheck).lower()[-4:]:
        return True
    elif "$" in str(textCheck).lower()[-4:]:
        return True
    elif "%" in str(textCheck).lower()[-4:]:
        return True

    return False

#-----------------------------------------------------------------
def telnet_cmd_prompt_root_check(textCheck):
#-----------------------------------------------------------------

    if "#" in str(textCheck).lower()[-4:]:
        return True

    return False


#-----------------------------------------------------------------
def telnet_unamePrompt_check(textCheck):
#-----------------------------------------------------------------

    if "e :" in str(textCheck).lower():
        return True

    elif "e:" in str(textCheck).lower():
        return True

    elif "n:" in str(textCheck).lower():
        return True

    elif "r:" in str(textCheck).lower():
        return True

    return False



#-----------------------------------------------------------------
def telnet_pwdPrompt_check(textCheck):
#-----------------------------------------------------------------

    if "d:" in str(textCheck).lower():
        return True

    elif "d :" in str(textCheck).lower():
        return True

    elif "d  :" in str(textCheck).lower():
        return True

    #this can lead to false positives
    #elif "assword" in str(textCheck).lower():
        #return True


    return False

#-----------------------------------------------------------------
def telnet_unauthorized_check(textCheck):
#-----------------------------------------------------------------

    if "warning" in str(textCheck).lower():
        return True
    elif "unauthorized" in str(textCheck).lower():
        return True
    elif "authorized" in str(textCheck).lower():
        return True

    return False

#-----------------------------------------------------------------
def print_vuln_device_info(ipaddress, port, username, pwd ):
#-----------------------------------------------------------------

    print(R + "\t*** Vulnerable: " + W + str(ipaddress) + ":" + str(port) + " : "+ O + str(username) + G + " : " + O + str(pwd) + W) 

#-----------------------------------------------------------------
def print_vuln_device_info_root(ipaddress, port, username, pwd ):
#-----------------------------------------------------------------

    print(R + "\t### Vulnerable AS ROOT/ADMIN: " + W + str(ipaddress) + ":" + str(port) + " : "+ O + str(username) + G + " : " + O + str(pwd) + W) 



#-----------------------------------------------------------------
def print_vuln_device_default(ipaddress, port, text):
#-----------------------------------------------------------------

    print(R + "\tVulnerable: " + W + str(ipaddress) + ":" + str(port) + " : "+ O + str(text) + W) 



#===================================================================================================
#    Start of brute forcing application
#===================================================================================================

#-------------------------------------------------------------------------
#     opening banner
#-------------------------------------------------------------------------

opening_msg = ""

opening_msg +=  "================================================================================\n"
opening_msg +=  "....." + R + "\t\t\tIoT Crusher v1.0 (Open Source)"  + W + "\n"
opening_msg +=  "....." + O + "\t  An IoT Telnet Device Default Credential Bruteforce Scanner" + W + " \n"
opening_msg +=  "....." + G + "\t\t\t  by OpCode 41 Security, Inc." + W + " \n"
opening_msg +=  "================================================================================\n"
opening_msg +=  "....." + B + " http://OpCode41.com\t@OpCode41\t@IoTCrusher\t@infosecmaverick\n" + W
opening_msg +=  "================================================================================\n"
opening_msg +=  ".....\n"
opening_msg +=  "....." + R + "\t  Go Pro! 9000+ device creds, multi-threaded, more protocols, &\n"  + W
opening_msg +=  "....." + R + "\tvirtually no account lockout(!) via our credential mapping technology!\n" + W
opening_msg +=  "....." + R + "\t\tContact us as well as for your pen-testing needs.\n" + W
opening_msg +=  ".....\n"
opening_msg +=  "....." + G + "\t\t\tPro versions: https://goo.gl/jJj28V \n" + W
opening_msg +=  ".....\n"
opening_msg +=  "--------------------------------------------------------------------------------\n"



#-------------------------------------------------------------------------
#     prep to test
#-------------------------------------------------------------------------

os.system('cls' if os.name == 'nt' else 'clear')
print(opening_msg)

print("--------------------------------------------------------------------------------")

cmdline_args = IoTcrusherBruteForceParms()
ipaddress_array = load_ip_addresses(str(cmdline_args["networkAddresses"]))
build_testing_usernames_passwords(cmdline_args['credList'])

respect_banner = False
if cmdline_args['checkBanner'] == 'True':
    respect_banner = True

#-------------------------------------------------------------------------
#     test ip addresses in supplied range
#-------------------------------------------------------------------------

print("--------------------------------------------------------------------------------")
print()

total_ip_addresses = len(ipaddress_array)
i = 0

for address in ipaddress_array:
#    processing / testing IP address 7/100 devices = % complete
    i += 1
    print("Now testing IP Address: " + str(address) + " \t-- " + str(i) + "/" + str(total_ip_addresses) + " Currently " + str(round((int(i)/int(total_ip_addresses))*100, 2)) + " % finished.")
    attack_telnet(str(address),"23", respect_banner)


#-------------------------------------------------------------------------
#     Thank you / Closing message
#-------------------------------------------------------------------------
print()
print("--------------------------------------------------------------------------------")
print(W + "\t\tThanks for running IoT Crusher Open Source!" + W)
print(G + "\t\t\tHope you found this valuable!" + W)
print(R + "\t\t     Pro versions: https://goo.gl/jJj28V" + W)
print("--------------------------------------------------------------------------------")


