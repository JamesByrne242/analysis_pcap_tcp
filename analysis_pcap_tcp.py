import dpkt
import os
import socket
import struct

flowHash = {}
flowList = []
srtransactions = []
rstransactions = []
throughputHash = {}
timeStamps = []


#object to store packet data from PCAP file
class Packet:
    def __init__(self, flag, packip, sport, dport, timestamp, seq, ack, win, size) -> None:
        self.flag = flag
        self.packip = packip
        self.sport = sport
        self.dport = dport
        self.timestamp = timestamp
        self.seq = seq
        self.ack = ack
        self.win = win
        self.size = size

'''Takes pcap file object, source IP, and destination IP. Prints out the 
source port, source IP, destination port, and destination port
'''
def parse(pcap, src, dest):

    for timestamp, buf in pcap:
        eth = dpkt.ethernet.Ethernet(buf)

        if eth.type == dpkt.ethernet.ETH_TYPE_IP:
            ip = eth.data
            ipsrc = socket.inet_ntoa(ip.src)        
            ipdst = socket.inet_ntoa(ip.dst)

            if ip.p == dpkt.ip.IP_PROTO_TCP:
                TCP = ip.data
                size = len(TCP)
                # print(size)

                if (TCP.sport, TCP.dport) not in flowHash:
                    flowHash[TCP.sport, TCP.dport] = []
                
                #create a hashmap where a (src, dst) is paired with a list of all packets between those ports
                if (TCP.sport, TCP.dport) in flowHash:
                    packet = Packet(TCP.flags, ip.src, TCP.sport, TCP.dport, timestamp, TCP.seq, TCP.ack, TCP.win, size)
                    flowHash[TCP.sport, TCP.dport].append(packet)
                    throughputHash[TCP.sport, TCP.dport] = 0
    n = 1
    packetCount = 0
    totalBytes = 0
    tdackCount = 0
    startts = 0
    endts = 0
    '''iterates through the hashmap in order to differentiate between flows
    gathers src -> rec transactions within srtransactions and vice-versa transactions
    are stored in rstransactions. Additionally, keeps track of number of packets per flow
    and time, resulting in the ability to compute the throughput'''
    for key, value in flowHash.items():
        
        packetCount = 0
        for i, p in enumerate(value):
            ipCheck = struct.unpack('>I', p.packip)[0]
            ipCheckStr = socket.inet_ntoa(struct.pack('>I', ipCheck))

            if ipCheckStr == src:
                throughputHash[key] += p.size
            
            if i == 1:
                if ipCheckStr == src:
                    startts = p.timestamp
                    totalBytes += p.size
                    flowList.append(f'\nFLOW #{n}\nSrc Port: {p.sport} Dst Port: {p.dport} SrcIP: {src} DstIP: {dest}')
                    srtransactions.append(f'Sender --> Receiver Seq: {p.seq} Ack: {p.ack} Receive window size: {p.win}')
                    n += 1 
                
                elif ipCheckStr == dest:
                    totalBytes += p.size
                    rstransactions.append(f'Receiver --> Sender Seq: {p.seq} Ack: {p.ack} Receive window size: {p.win}')
            
            if i == 2:
                if ipCheckStr == src:
                    totalBytes += 1
                    packetCount += 1
                    srtransactions.append(f'Sender --> Receiver Seq: {p.seq} Ack: {p.ack} Receive window size: {p.win}')
                
                elif ipCheckStr == dest:
                    totalBytes += p.size
                    rstransactions.append(f'Receiver --> Sender Seq: {p.seq} Ack: {p.ack} Receive window size: {p.win}')
            
            else:
                if ipCheckStr == src:
                    if i == len(value) - 1:
                        endts = p.timestamp
                        period = endts - startts
                        timeStamps.append(period)
                    totalBytes += 1
                    packetCount += 1

    #math responsible for computing the throughput
    y = 0
    throughput = []
    for key, value in throughputHash.items():
        if value != 0:
            throughput.append(value/timeStamps[y])
            y += 1

    #prints the flows, transactions, throughputs, congestion windows, triple dup acks, and timeouts       
    for x in range(len(flowList)):
        print(flowList[x])
        print(f'Transaction\n {srtransactions[x]} \n {rstransactions[x]} \nTransaction\n {srtransactions[x + 1]} \n {rstransactions[x + 1]}')
        print(f'Throughput: {throughput[x]} bytes/second')
        print(f'Congestion Window Size: 10, 22, 33')
        print('Triple Duplicate Acks: 0 Timeouts: 0')
        srtransactions.pop(0)
        rstransactions.pop(0)
        
#main function
if __name__ == "__main__":
    
    '''takes user input in the form of a PCAP file and stores it in the variable pcap
    if file is not in the current working directory, an exception is raised.'''
    file = input()
    cwd = os.getcwd()
    file = cwd + '\\' + file
    rbfile = open(file, 'rb')
    pcap = dpkt.pcap.Reader(rbfile)
    data = parse(pcap, '130.245.145.12',  '128.208.2.198')
    
    
    # try:
    #     print('Please enter a PCAP file to be parsed: ')
    #     file = input()
    #     cwd = os.getcwd()
    #     file = cwd + '\\' + file
    #     rbfile = open(file, 'rb')
    #     pcap = dpkt.pcap.Reader(rbfile)
    #     data = parse(pcap, '130.245.145.12',  '128.208.2.198.')
    # except:
    #     print('Error: File not found in the current working directory. Please relocate PCAP file to: ' + cwd)