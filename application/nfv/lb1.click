//define counter
input1, output1, input2, output2 :: AverageCounter;
arp_req1, arp_res1, ip1 :: Counter;
arp_req2, arp_res2, ip2 :: Counter;
icmp, drop1, drop2, drop3 :: Counter;


// from client to server
from_client :: FromDevice(lb8-eth2, METHOD LINUX, SNIFFER false);
to_server :: Queue -> output2 -> ToDevice(lb8-eth1, METHOD LINUX);


// from server to client
from_server :: FromDevice(lb8-eth1, METHOD LINUX, SNIFFER false);
to_client :: Queue -> output1 -> ToDevice(lb8-eth2, METHOD LINUX);


// Packet classifier
client_classifier, server_classifier :: Classifier(
	12/0806 20/0001, //[0]ARP request
	12/0806 20/0002, //[1]ARP reply
	12/0800,		 //[2]IP
	-);				 //[3]rest

	
// ARP querier
server_arpq :: ARPQuerier(100.0.0.25, lb8-eth1);
client_arpq :: ARPQuerier(100.0.0.25, lb8-eth2);


// IP packet
ip_to_client :: GetIPAddress(16) -> CheckIPHeader -> [0]client_arpq -> IPPrint("Ip packet to client") -> to_client;
ip_to_server :: GetIPAddress(16) -> CheckIPHeader -> [0]server_arpq -> IPPrint("Ip packet to server") -> to_server;


// round robin, IP rewrite
round_robin :: RoundRobinIPMapper(
	100.0.0.25 - 100.0.0.20 53 0 1, 
	100.0.0.25 - 100.0.0.21 53 0 1, 
	100.0.0.25 - 100.0.0.22 53 0 1);
ip_rewrite :: IPRewriter(round_robin, pattern 100.0.0.25 20000-65535 - -  1 0);
ip_rewrite[0] -> ip_to_server;
ip_rewrite[1] -> ip_to_client;


// packet from server 
from_server -> input2 -> server_classifier;
server_classifier[0] -> arp_req2 -> ARPResponder(100.0.0.25 lb8-eth1) -> to_server; //ARP request
server_classifier[1] -> arp_res2 -> [1]server_arpq; //ARP reply
server_classifier[2] -> ip2 -> Strip(14) -> CheckIPHeader -> IPPrint("IP packet from server") -> [1]ip_rewrite; //IP packet
server_classifier[3] -> drop2 -> Discard; //Drop rest packet


// packet from client 
from_client -> input1 -> client_classifier;
client_classifier[0] -> arp_req1 -> ARPResponder(100.0.0.25 lb8-eth2) -> to_client; //ARP request
client_classifier[1] -> arp_res1 -> [1]client_arpq; //ARP reply
client_classifier[2] -> ip1 -> Strip(14) -> CheckIPHeader -> IPPrint("IP packet from client") -> client_IP_classifier :: IPClassifier(icmp, dst udp port 53, -); //IP packet
	client_IP_classifier[0] -> icmp -> icmppr :: ICMPPingResponder() -> ip_to_client; //ICMP
	client_IP_classifier[1] -> [0]ip_rewrite; //UDP
	client_IP_classifier[2] -> drop3 -> Discard; //rest
client_classifier[3] -> drop1 -> Discard; //Drop rest packet


//Report
DriverManager(wait , print > ../results/lb1.report  "
	=================== LB1 Report ===================
	Input Packet Rate (pps): $(add $(input1.rate) $(input2.rate))
	Output Packet Rate(pps): $(add $(output1.rate) $(output2.rate))

	Total # of input packets: $(add $(input1.count) $(input2.count))
	Total # of output packets: $(add $(output1.count) $(output2.count))

	Total # of ARP requests packets: $(add $(arp_req1.count) $(arp_req2.count))
	Total # of ARP respondes packets: $(add $(arp_res1.count) $(arp_res2.count))

	Total # of service requests packets: $(add $(ip1.count) $(ip2.count))
	Total # of ICMP packets: $(icmp.count)
	Total # of dropped packets: $(add $(drop1.count) $(drop2.count) $(drop3.count))
	================================================== 
" , stop);
