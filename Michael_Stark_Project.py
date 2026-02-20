from pprint import pprint
# Requests library
import requests
response = requests.get('https://www.michaelbryanstark.com/')
# Request to get a responce from url
print(response)
#prints the response, output ==> <Response [200]>

# Check the response status code
if response.status_code == 200:
    print('Request successful')
else:
    print('Request failed')
    
pprint(response.text)
# prints out html of page
pprint(response.content)
# Prints out a response body as bytes for non-text requests i.e. images

# Passing parameters in to URLS
payload = {'key1': 'value1', 'key2': 'value2'}
response = requests.get('https://www.michaelbryanstark.com/', params=payload)
print(response.url)
# output ==> https://www.michaelbryanstark.com/?key1=value1&key2=value2
# Useful in detecting web paramater tampering

response = requests.get('https://api.github.com/events')
pprint(response.json())
# Prints out json data

# Cryptography Library
# from cryptography.fernet import Fernet
# key = Fernet.generate_key()
# f = Fernet(key)
# token = f.encrypt(b"You can not read this message until you have the key to decrypt it!!")
# # creates an encrypted token of the message
# print(token)
# # output ==> b'gAAAAABpimucZcr5EDmnVV2LsFs9i9UidENcPPVeKct5B8IawmXW0oh3N8rqENFlb_uO-2EnrFXSEHQd5lP2Lt-egxD56kM1A6HDcv3isixb7p3QsenoHhoy1B98V9on1JyPjVdrxZ7wBoW5LvpchUtDLcaiZj_-GWskazh5GMGuEIlrzH2yVyg='

# print(f.decrypt(token))
# # decrypts and prints original message
# # output ==> b'You can not read this message until you have the key to decrypt it!!'

# # simple port scanner with nmap
# import nmap
# nm = nmap.PortScanner()

# target = '45.33.32.156'
# # the ip address you want to scan (using the test ip provided by nmap but can replace with any ip authorized to scan)
# options = '-sV -sC scan_results'
# # sV gives version sC runs standard nmap script

# nm.scan(target, arguments=options)
# # calls the scan method from nmap to perform network scan using the two arguments target and options

# for host in nm.all_hosts():
#     #iterates through lists of hosts 
#     print("Host: %s (%s)" % (host, nm[host].hostname()))
#     print("State: %s" % nm[host].state())
#     for protocol in nm[host].all_protocols():
#         #iterates through list protocols used by the individual hosts scanned
#         print("Protocol: %s" % protocol)
#         port_info = nm[host][protocol]
#         for port, state in port_info.items():
#             # iterate through list of ports and their states for current protocol
#             print("Port: %s\tState: %s" % (port, state))

# # output
# # Host: 45.33.32.156 (scanme.nmap.org)
# # State: up
# # Protocol: tcp
# # Port: 22        State: {'state': 'open', 'reason': 'syn-ack', 'name': 'ssh', 'product': 'OpenSSH', 'version': '6.6.1p1 Ubuntu 2ubuntu2.13', 'extrainfo': 'Ubuntu Linux; protocol 2.0', 'conf': '10', 'cpe': 'cpe:/o:linux:linux_kernel', 'script': {'ssh-hostkey': '\n  1024 ac:00:a0:1a:82:ff:cc:55:99:dc:67:2b:34:97:6b:75 (DSA)\n  2048 20:3d:2d:44:62:2a:b0:5a:9d:b5:b3:05:14:c2:a6:b2 (RSA)\n  256 96:02:bb:5e:57:54:1c:4e:45:2f:56:4c:4a:24:b2:57 (ECDSA)\n  256 33:fa:91:0f:e0:e1:7b:1f:6d:05:a2:b0:f1:54:41:56 (ED25519)'}}
# # Port: 80        State: {'state': 'open', 'reason': 'syn-ack', 'name': 'http', 'product': 'Apache httpd', 'version': '2.4.7', 'extrainfo': '(Ubuntu)', 'conf': '10', 'cpe': 'cpe:/a:apache:http_server:2.4.7', 'script': {'http-favicon': 'Nmap Project', 'http-title': 'Go ahead and ScanMe!', 'http-server-header': 'Apache/2.4.7 (Ubuntu)'}}
# # Port: 9929      State: {'state': 'open', 'reason': 'syn-ack', 'name': 'nping-echo', 'product': 'Nping echo', 'version': '', 'extrainfo': '', 'conf': '10', 'cpe': ''}
# # Port: 31337     State: {'state': 'open', 'reason': 'syn-ack', 'name': 'tcpwrapped', 'product': '', 'version': '', 'extrainfo': '', 'conf': '8', 'cpe': ''}