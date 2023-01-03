import dpkt
import sys

def ipToString(addr):
    retStr = ""
    for c in addr:
        retStr += str(c) + '.'
    return retStr[:len(retStr)-1]

# Flags:
# SYN = 0x2 (bit 1)
# ACK = 0x010 (bit 4)
# PSH = 0x8 (bit 3)
# FIN = 0x1 (bit 0)
def displayFlag(transaction):
    flag = transaction.flags
    retStr = ""
    if(flag & 1 != 0): retStr += "FIN "
    if(flag & (1 << 1) != 0): retStr += "SYN "
    if(flag & (1 << 3) != 0): retStr += "PSH "
    if(flag & (1 << 4) != 0): retStr += "ACK "
    return retStr[:len(retStr)-1]

def displayTransaction(transaction, windowScale):
    print("SEQ: {}, ACK: {}, Receive Window: {}"
        .format(transaction.seq, transaction.ack, transaction.win*(2<<(windowScale-1))))

def analyze(fileName):
    # Open file
    f = open(fileName, "rb")
    pcap = dpkt.pcap.Reader(f)

    packets = []
    for ts, buf in pcap:
        eth = dpkt.ethernet.Ethernet(buf)
        packets.append((eth,ts))

    srcIP = packets[0][0].data.src
    dstIP = packets[0][0].data.dst

    flows = []
    flowContents = []
    for packet in packets:
        ip = packet[0].data
        tcp = ip.data
        # Sender -> Receiver
        if(ip.src == srcIP and ip.dst == dstIP):
            if(tcp.sport, tcp.dport) not in flows:
                flows.append((tcp.sport, tcp.dport))
                newList = [(ip,packet[1])]
                flowContents.append(newList)
            else:
                flowContents[flows.index((tcp.sport, tcp.dport))].append((ip,packet[1]))
        # Receiver -> Sender
        else:
            flowContents[flows.index((tcp.dport, tcp.sport))].append((ip,packet[1]))

    print("Number of TCP Flows: {}".format(len(flows)))
    print("(source port, source IP, dest port, dest IP)")
    print()
    # Part A, (a)-(c)
    for i in range(3):
        print("Flow #"+str(i+1)+":")
        # Print the source port, srcIP, destination port and the dstIP
        print("({}, {}, {}, {})".format(flows[i][0], ipToString(srcIP), flows[i][1], ipToString(dstIP)))
        options = dpkt.tcp.parse_opts(flowContents[2][0][0].data.opts)
        windowScale = options[5][1][0]

        # Print the first two transactions after the three way handshake
        for j in range(3,5):
            displayTransaction(flowContents[i][j][0].data, windowScale)
        
        # Print the sender throughput
        # Go through the packets in this flow that the sender has sent.
        # Starting with the first ack after the three way handshake,
        # accumulate the amount of data
        # that the sender has sent + 32 for the TCP header, up until the
        # FIN packet
        totalData = 0
        firstTime = flowContents[i][3][1]
        lastTime = 0
        for packet in flowContents[i][3:]:
            if(packet[0].data.sport == flows[i][0] and packet[0].data.dport == flows[i][1]):
                totalData += packet[0].len
                totalData -= 4*packet[0].hl
                if(packet[0].data.flags & 1 == 1):
                    lastTime = flowContents[i][flowContents[i].index(packet)][1]
                    break
        print("Throughput: {} bytes/sec".format(totalData/(lastTime-firstTime)))

        # Congestion window:
        # Start with the first sent packet, and add all the packets
        # that are sent from the sender to the receiver into
        # a buffer. When the ack for the first or second packet is returned,
        # print out the current window size and empty the packet buffer. The next two packets
        # that are sent will be the next point at which you
        # wait for the acknowledgment. Repeat the same procedure
        # for a total of three resets or until the flow temrinates.
        print("Congestion windows:")
        uniquePackets = []
        numWindowSizes = 0
        for packet in flowContents[i][3:]:
            tcp = packet[0].data
            if(numWindowSizes == 3): break
            # Sender -> Receiver
            if(tcp.sport == flows[i][0] and tcp.dport == flows[i][1]):
                uniquePackets.append(tcp.seq)
            # Receiver -> Sender
            else:
                if(tcp.ack in uniquePackets[0:2]):
                    numWindowSizes += 1
                    print(len(uniquePackets))
                    uniquePackets = []
        if(numWindowSizes < 3): print(len(uniquePackets))

        # Fast retransmission vs. timeout
        # Keep track of the sequence numbers of the
        # packets that have been sent in an array,
        # and the number of acknowledgments that have been sent with
        # the ack number being equal to any of the sequence numbers in the
        # same array. 
        # If at any point a packet with the same sequence number is sent again,
        # look at how many acks have been sent requesting for that sequence number.
        # If that number is >= 3, increment the fast retransmission counter, otherwise
        # increment the timeout counter. Reset the number of acks sent to 0 as well.
        sequenceNumbers = []
        acknowledgments = []
        tripleDups = 0
        timeouts = 0
        for packet in flowContents[i][3:]:
            tcp = packet[0].data
            # Sender -> Receiver
            if(tcp.sport == flows[i][0] and tcp.dport == flows[i][1]):
                if(tcp.seq not in sequenceNumbers):
                    sequenceNumbers.append(tcp.seq)
                    acknowledgments.append(0)
                else:
                    ind = sequenceNumbers.index(tcp.seq)
                    if(acknowledgments[ind] >= 3):
                        tripleDups += 1
                    else:
                        timeouts += 1
                    acknowledgments[ind] = 0
            # Receiver -> Sender
            else:
                if(tcp.ack in sequenceNumbers):
                    ind = sequenceNumbers.index(tcp.ack)
                    acknowledgments[ind] = acknowledgments[ind]+1         
        print("Retransmissions due to triple duplicate acks: {}".format(tripleDups))
        print("Retransmissions due to timeout: {}".format(timeouts))
        print()

def main():
    if(len(sys.argv) != 2):
        print("Please enter a single valid pcap file.")
    else:
        analyze(sys.argv[1])

main()