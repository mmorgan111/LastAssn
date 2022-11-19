from socket import *
import os
import sys
import struct
import time
import select
import binascii
import pandas as pd

ICMP_ECHO_REQUEST = 8
MAX_HOPS = 30
TIMEOUT = 2.0
TRIES = 1
# The packet that we shall send to each router along the path is the ICMP echo
# request packet, which is exactly what we had used in the ICMP ping exercise.
# We shall use the same packet that we built in the Ping exercise

def checksum(string):
# In this function we make the checksum of our packet
    csum = 0
    countTo = (len(string) // 2) * 2
    count = 0

    while count < countTo:
        thisVal = (string[count + 1]) * 256 + (string[count])
        csum += thisVal
        csum &= 0xffffffff
        count += 2

    if countTo < len(string):
        csum += (string[len(string) - 1])
        csum &= 0xffffffff

    csum = (csum >> 16) + (csum & 0xffff)
    csum = csum + (csum >> 16)
    answer = ~csum
    answer = answer & 0xffff
    answer = answer >> 8 | (answer << 8 & 0xff00)
    return answer

def build_packet():
    #Fill in start
    # In the sendOnePing() method of the ICMP Ping exercise ,firstly the header of our
    # packet to be sent was made, secondly the checksum was appended to the header and
    # then finally the complete packet was sent to the destination.

    # Make the header in a similar way to the ping exercise.
    # Append checksum to the header.
    myChecksum = 0
    ID = 0
    header = struct.pack("bbHHh", ICMP_ECHO_REQUEST, 0, myChecksum, ID, 1)
    data = struct.pack("d", time.time())

    # Don’t send the packet yet , just return the final packet in this function.
    #Fill in end

    # So the function ending should look like this

    packet = header + data
    return packet

def get_route(hostname):
    timeLeft = TIMEOUT
    df = pd.DataFrame(columns=['Hop Count', 'Try', 'IP', 'Hostname', 'Response Code'])

    for ttl in range(1,MAX_HOPS):
        for tries in range(TRIES):
            destAddr = gethostbyname(hostname)

            #Fill in start
            # Make a raw socket named mySocket
            icmp = getprotobyname("icmp")
            mySocket = socket(AF_INET, SOCK_RAW, icmp)
            #Fill in end

            mySocket.setsockopt(IPPROTO_IP, IP_TTL, struct.pack('I', ttl))
            mySocket.settimeout(TIMEOUT)
            try:
                d = build_packet()
                mySocket.sendto(d, (hostname, 0))
                t= time.time()
                startedSelect = time.time()
                whatReady = select.select([mySocket], [], [], timeLeft)
                howLongInSelect = (time.time() - startedSelect)
                if whatReady[0] == []: # Timeout
                    #Fill in start
                    #append response to your dataframe including hop #, try #, and "Timeout" responses as required by the acceptance criteria
                    df.append({'Hop Count': str(MAX_HOPS), 'Try': str(tries), 'IP': str('timeout'), 'Hostname': str('timeout'), 'Response Code': str('timeout')},
                            ignore_index=True)
                    print (df)
                    #Fill in end
                recvPacket, addr = mySocket.recvfrom(1024)
                timeReceived = time.time()
                timeLeft = timeLeft - howLongInSelect
                if timeLeft <= 0:
                    #Fill in start
                    #append response to your dataframe including hop #, try #, and "Timeout" responses as required by the acceptance criteria
                    df.append({'Hop Count': str(MAX_HOPS), 'Try': str(tries), 'IP': str('timeout'), 'Hostname': str('timeout'), 'Response Code': str('timeout')},
                              ignore_index=True)
                    print (df)
                    #Fill in end
            except Exception as e:
                print (e) # uncomment to view exceptions
                continue

            else:
                #Fill in start
                #Fetch the icmp type from the IP packet
                types, = struct.unpack('b', recvPacket[20:21])

                #Fill in end
                try: #try to fetch the hostname
                    #Fill in start
                    hostname = gethostbyaddr(addr[0])[0]
                    #Fill in end
                except herror:   #if the host does not provide a hostname
                    #Fill in start
                    hostname = "hostname not returnable"
                    #Fill in end

                if types == 11:
                    bytes = struct.calcsize("d")
                    timeSent = struct.unpack("d", recvPacket[28:28 +
                    bytes])[0]
                    #Fill in start
                    #You should update your dataframe with the required column field responses here
                    df.append({'Hop Count': str(tries), 'Try': str(TRIES), 'IP': str(destAddr), 'Hostname': str(hostname), 'Response Code': str(0)},
                              ignore_index=True)
                    #Fill in end
                elif types == 3:
                    bytes = struct.calcsize("d")
                    timeSent = struct.unpack("d", recvPacket[28:28 + bytes])[0]
                    #Fill in start
                    #You should update your dataframe with the required column field responses here
                    df.append({'Hop Count': str(tries), 'Try': str(TRIES), 'IP': str(destAddr), 'Hostname': str(hostname), 'Response Code': str(0)},
                              ignore_index=True)
                    #Fill in end
                elif types == 0:
                    bytes = struct.calcsize("d")
                    timeSent = struct.unpack("d", recvPacket[28:28 + bytes])[0]
                    df.append({'Hop Count': str(tries), 'Try': str(TRIES), 'IP': str(destAddr), 'Hostname': str(hostname), 'Response Code': str(0)},
                              ignore_index=True)
                    #Fill in start
                    #You should update your dataframe with the required column field responses here
                    #Fill in end
                else:
                    #Fill in start
                    #If there is an exception/error to your if statements, you should append that to your df here
                    df.append({'Hop Count': str(tries), 'Try': str(TRIES), 'IP': str(destAddr), 'Hostname': str(hostname), 'Response Code': str(0)},
                              ignore_index=True)
                    #Fill in end
                break
    return df


get_route("google.co.il")