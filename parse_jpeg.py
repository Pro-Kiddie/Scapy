from scapy.all import *

def filter_packets(file, src, sport):
    a = rdpcap(file)
    sessions = a.sessions()
    for session in sessions:
        for packet in sessions[session]:
            if packet.haslayer(IP) and packet.haslayer(TCP) and packet[IP].src == src and packet[TCP].sport == sport:
                wrpcap("filtered.pcap", packet, append=True)

def extract_image(file):
    a = rdpcap(file)
    sessions = a.sessions()
    counter = 0
    for session in sessions:
        jpeg = b""
        for packet in sessions[session]: # Already filtered the packets to only include IP and TCP packets
            payload = bytes(packet[TCP].payload)
            start_jpeg = payload.find(b"--frame\r\nContent-Type: image/jpeg\r\n\r\n") # Can find the jpeg file header 0xFFD8 too
            # if start_jpeg != -1:
            #     print(payload[start_jpeg+37:])
            if start_jpeg == -1: 
                jpeg += payload
            else: # found the start of jpeg image
                if start_jpeg > 2: # append the data before the HTTP header
                    jpeg += payload[:start_jpeg-2]
                if len(jpeg) != 0: # prevent the 0.jpg with size 0 from being saved for the first frame packet with --frame at start of the HTTP payload
                    with open("output/{}.jpg".format(counter), "wb") as f: 
                            f.write(jpeg)
                counter += 1
                # reset jpeg to the data after header 
                jpeg = payload[start_jpeg+37:] # len(b"--frame\r\nContent-Type: image/jpeg\r\n\r\n") = 37

if __name__ == '__main__':
    #filter_packets("videofeed.pcap", "192.168.1.141", 5000)
    extract_image("test.pcap")