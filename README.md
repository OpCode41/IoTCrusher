# IoTCrusher (Open Source) v1.0
Use IoT Crusher to scan networks and brute force default credentials on telnet for multiple device types, including embedded devices, legacy network devices, medical, and IoT devices. 
==

Contents
--
1. Business Case: Default Credentials
2. Two Issues: Non-centrally Managed Devices / Change Management & Malware 
3. Brute Forcing Issues
4. Optimized Credentials for IoT Crusher Open Source
5. Three Application Architectures
6. Running IoTCrusher Open Source
7. To Do
8. Contact


1. Business Case: Default Credentials
--

Default credentials are more prevalent than tested for as many professional scanners do not conduct brute force testing by default unless specially configured to run this test type. Professional pen-testers often stay away from brute forcing due to time and account lockouts. 

The result is a lot of low hanging fruit in organizations that is frequently overlooked and not reported.


2. Two Issues: Non-centrally Managed Devices / Change Management & Malware
--

Non-centrally Managed Devices: 
Devices that are not centrally managed are more likely to be vulnerable because changes on them -- including leaving the default configuration as well as password resets -- are invisible to the manager. This means that change management is almost impossible for leading to both inventory issues on the business side and cyber security issues on the other

Malware:
Recent malware such as the Mirai and Hajime have demonstrated the scope of the issue as well as the central issue itself: default, weak, and hard coded credentials.


3. Brute Forcing Issues
--

Traditionally brute forcing accounts takes time: it is normally conducted with large lists downloaded from prior breaches. It is also repeated attempts are prone to account lockout.


4. Optimized Credentials for IoT Crusher Open Source
--

Credential as of 15 November 2017 include, malware such as Mirai and Hajime, the recent pastebin IoT credential dump, and a handful of embedded device vendors. 

Use All lists or any combination thereof. When merged, the list will be optimized to have only a single instance of each credential pair, streamlining the test with only valid credentials.


5. Three Application Architectures
--

IoT Crusher comes in open source, professional, and enterprise versions. Please note they are three different code bases under one name/brand. 

The professional and enterprise versions are much more robust, have a great deal more optimization features, and focuses on over 9000+ devices by manufacture and type. 

Both may be found here: https://opcode41.com/shop/


6. Running IoTCrusher Open Source
--

Make sure you have python 3 installed.

Download 
chmod 755 IoTCrusherOpenSource.py
./IoTCrusherOpenSource.py -h

(Not tested on Windows, just Kali and Ubuntu.)


7. To Do
--

1. Create a nice front end
2. Add more credential sets 
3. Test a port on Windows


8. Contact
--

Please contact us through the website: https://opcode41.com

