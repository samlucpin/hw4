import socket
import socketserver
from ipaddress import ip_address, IPv4Address
import os
#os.system('pip install cymruwhois')
from cymruwhois import Client

def typeIP(IP: str) -> str:
    try:
        return "IPv4" if type(ip_address(IP)) is IPv4Address else "IPv6"
    except ValueError:
        return "Invalid"

def IPV4_ADDR(domain):
    addr = socket.gethostbyname(domain)
    if typeIP(addr) == "IPv4":
        return addr
    else:
        return "This domain does not use a IPv4 Address"
    return "?IPv4?"

def IPV6_ADDR(domain):
    addr = socket.gethostbyname(domain)
    if typeIP(addr) == "IPv6":
        return addr
    else:
        return "This domain does not use a IPv6 Address"
    return "?IPv6?"

def TLS_CERT(domain):
    try:
        import ssl
    except ImportError:
        pass
    else:
        context = ssl.create_default_context()
        conn = context.wrap_socket(socket.socket(), server_hostname=domain)
        conn.connect((domain, 443))
        cert = conn.getpeercert()
        return cert

def HOSTING_AS(domain):
    cymru = Client()
    addr = socket.gethostbyname(domain)
    r = cymru.lookup(addr)
    return r.owner

def ORGANIZATION(domain):
    cymru = Client()
    addr = socket.gethostbyname(domain)
    r = cymru.lookup(addr)
    tls = TLS_CERT(domain)
    argDict = dict(x[0] for x in tls['issuer'])
    return argDict['commonName']

def runServer():
    response = ""
    serverSock = socket.socket()
    serverSock.bind(('127.0.0.1', 5555))
    serverSock.listen()
    conn, addr = serverSock.accept()
    strT = conn.recv(1024).decode()
    spltSpot = strT.index(',')
    dom = strT[:spltSpot]
    service = strT[spltSpot+1:]
    if (service=="IPV4_ADDR"):
        response = IPV4_ADDR(dom)
    elif (service=="IPV6_ADDR"):
        response = IPV6_ADDR(dom)
    elif (service=="TLS_CERT"):
        response = str(TLS_CERT(dom))
    elif (service=="HOSTING_AS"):
        response = HOSTING_AS(dom)
    elif (service=="ORGANIZATION"):
        response = ORGANIZATION(dom)
    else:
        response = "Not A Valid Service Name"
    conn.send(response.encode())
    serverSock.close()
    conn.close()

if __name__ == '__main__':
    runServer()
