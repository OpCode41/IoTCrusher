# IoTCrusher (Open Source) v1.0
Use IoT Crusher to scan networks and brute force default credentials on telnet for multiple device types, including embedded devices, legacy network devices, medical, and IoT devices. 
--

Contents
--
* Business Case: Default Credentials
* Two Issues: Non-centrally Managed Devices / Change Management & Malware 
* Brute Forcing Issues
* Optimized Credentials for IoT Crusher Open Source
* Three Application Architectures
* Running IoTCrusher Open Source
* To Do
* Contact


Business Case: Default Credentials
--

Default credentials are more prevalent than tested for as many professional scanners do not conduct brute force testing by default unless specially configured to run this test type. Professional pen-testers often stay away from brute forcing due to time and account lockouts. 

The result is a lot of low hanging fruit in organizations that is frequently overlooked and not reported.


Two Issues: Non-centrally Managed Devices / Change Management & Malware
--

Non-centrally Managed Devices: 
Devices that are not centrally managed are more likely to be vulnerable because changes on them -- including leaving the default configuration as well as password resets -- are invisible to the manager. This means that change management is almost impossible for leading to both inventory issues on the business side and cyber security issues on the other

Malware:
Recent malware such as the Mirai and Hajime have demonstrated the scope of the issue as well as the central issue itself: default, weak, and hard coded credentials.


Brute Forcing Issues
--

Traditionally brute forcing accounts takes time: it is normally conducted with large lists downloaded from prior breaches. It is also repeated attempts are prone to account lockout.


Optimized Credentials for IoT Crusher Open Source
--

Credentials as of 15 November 2017 include malware such as Mirai and Hajime, the recent pastebin IoT credential dump, and a handful of embedded device vendor default user names and passwords. 

Use 'All' lists or any combination thereof. When merged, the list will be optimized to have only a single instance of each credential pair, streamlining the test with only valid credentials.


Three Application Architectures
--

IoT Crusher comes in open source, professional, and enterprise versions. Please note they are three different code bases under one name/brand. 

The professional and enterprise versions are much more robust, have a great deal more optimization features, and focuses on over 9000+ devices by manufacture and type. 

Both may be found here: https://opcode41.com/shop/


Running IoTCrusher Open Source
--

Make sure you have python 3 installed.

```
Download 
chmod 755 IoTCrusherOpenSource.py
./IoTCrusherOpenSource.py -h
```

(Not tested on Windows, just Kali and Ubuntu.)


To Do
--

* Create a nice front end
* Add more credential sets 
* Test a port on Windows


Contact
--

Please contact us through the website: https://opcode41.com
--
