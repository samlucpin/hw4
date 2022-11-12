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
        conn = context.wrap_socket(socket.socket(AF_INET), server_hostname=domain)
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
    domConfirm = "GotDom"
    response = ""
    serverSock = socket.socket()
    serverSock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, True)
    serverSock.bind(('127.0.0.1', 5555))
    serverSock.listen(5)
    conn, addr = serverSock.accept()
    dom = conn.recv(1024)
    conn.send(domConfirm.encode())
    service = conn.recv(1024)
    #data = conn.recv(1024)
    #dom = data[0].decode()
    #service = data[1].decode()
    if (service=="IPV4_ADDR"):
        response = IPV4_ADDR(dom)
    elif (service=="IPV6_ADDR"):
        response = IPV6_ADDR(dom)
    elif (service=="TLS_CERT"):
        response = TLS_CERT(dom)
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

#class TCPHand(socketserver.BaseRequestHandler):

 #   def handle(self):
  #      self.data = self.request.recv(1024).strip()
   #     print("{} wrote:".format(self.client_address[0]))
    #    print(self.data)
     #   self.request.sendall(self.data.upper())


#def main():

   # return

#if __name__ == "__main__":

 #   HOST, PORT = "127.0.0.1", 5555

  #  with socketserver.TCPServer((HOST, PORT), TCPHand) as server:

   #     server.serve_forever()



#sockTCP = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
#server = socket.create_server(("127.0.0.1", 5555), family=socket.AF_INET, dualstack_ipv6=False)
#server.bind(("127.0.0.1", 5555))
