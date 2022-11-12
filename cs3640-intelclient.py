import socket
from argparse import ArgumentParser

def runClient(sAddr,sPort,domain,service):
    sockClient = socket.socket()
    sockClient.connect((sAddr, sPort))
    tupe = (domain, service)
    strT = ','.join([str(i) for i in tupe])
    sockClient.send(strT.encode())
    response = sockClient.recv(1024).decode()

    sockClient.close()
    
    return response

def main(intel_server_addr, intel_server_port, domain, service):
    return runClient(intel_server_addr, intel_server_port, domain, service)

if __name__ == "__main__":
    argParser = ArgumentParser()
    argParser.add_argument(
            "-intel_server_addr",
            type=str,
            default="127.0.0.1",
            help="IP Address of the Intel Server"
        )
    argParser.add_argument(
            "-intel_server_port",
            type=int,
            default=5555,
            help="Port of the Intel Server"
        )
    argParser.add_argument(
            "-domain",
            type=str,
            default="www.google.com",
            help="Web Domain you want to use a service on"
        )
    argParser.add_argument(
            "-service",
            type=str,
            default="IPV4_ADDR",
            help="The Service you want to use on the domain"
        )
    args = argParser.parse_args()
    final = main(args.intel_server_addr, args.intel_server_port, args.domain, args.service)
    print(final)
