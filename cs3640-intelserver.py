import socket
import socketserver
import dnspython
from ipaddress import ip_address, IPv4Address
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
    serverSock = socket.socket()
    serverSock.bind(('127.0.0.1', 5555))
    serverSock.listen(2)
    conn, addr = serverSock.accept()
    while True:
        data = conn.recv(1024).decode()
        if not data:
            break
        #print("from connected user: " + str(data))
        data = "tester"
        conn.send(data.encode())
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
