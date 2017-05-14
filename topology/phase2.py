from mininet.topo import Topo
from mininet.net import Mininet
from mininet.node import RemoteController
from mininet.cli import CLI
from mininet.log import setLogLevel, info
import sys
import time
import os

PHASE1_LOG = os.path.expanduser('~') + '/ik2220-assign-phase2-team6/results/phase_2_report'

class MyTopo(Topo):

    def __init__( self ):
        Topo.__init__( self )

	h1 = self.addHost('h1', ip = '100.0.0.10/24', mac='00:00:00:00:00:10', defaultRoute='via 100.0.0.1')
	h2 = self.addHost('h2', ip = '100.0.0.11/24', mac='00:00:00:00:00:11', defaultRoute='via 100.0.0.1')
	h3 = self.addHost('h3', ip = '10.0.0.50/24', mac='00:00:00:00:00:50', defaultRoute='via 10.0.0.1')
	h4 = self.addHost('h4', ip = '10.0.0.51/24', mac='00:00:00:00:00:51', defaultRoute='via 10.0.0.1')

	ds1 = self.addHost('ds1', ip = '100.0.0.20/24', mac='00:00:00:00:00:20')
	ds2 = self.addHost('ds2', ip = '100.0.0.21/24', mac='00:00:00:00:00:21')
	ds3 = self.addHost('ds3', ip = '100.0.0.22/24', mac='00:00:00:00:00:22')

	ws1 = self.addHost('ws1', ip = '100.0.0.40/24', mac='00:00:00:00:00:40')
	ws2 = self.addHost('ws2', ip = '100.0.0.41/24', mac='00:00:00:00:00:41')
	ws3 = self.addHost('ws3', ip = '100.0.0.42/24', mac='00:00:00:00:00:42')

	insp = self.addHost('insp', ip = '100.0.0.30/24', mac='00:00:00:00:00:30')

	sw1 = self.addSwitch('sw1')
	sw2 = self.addSwitch('sw2')
	sw3 = self.addSwitch('sw3')
	sw4 = self.addSwitch('sw4')
	sw5 = self.addSwitch('sw5')

	fw1 = self.addSwitch('fw6')
	fw2 = self.addSwitch('fw7')

	lb1 = self.addSwitch('lb8')
	lb2 = self.addSwitch('lb9')

	ids = self.addSwitch('ids10')
	napt = self.addSwitch('napt11')

	self.addLink(ds1,sw3)
	self.addLink(ds2,sw3)
	self.addLink(ds3,sw3)
	self.addLink(sw3,lb1)
	self.addLink(lb1,sw2)
	self.addLink(sw2,ids)
	self.addLink(ids,insp)
	self.addLink(ids,lb2)
	self.addLink(lb2,sw4)
	self.addLink(sw4,ws1)
	self.addLink(sw4,ws2)
	self.addLink(sw4,ws3)
	self.addLink(sw1,h1)
	self.addLink(sw1,h2)
	self.addLink(sw1,fw1)
	self.addLink(fw1,sw2)
	self.addLink(sw2,fw2)
	self.addLink(fw2,napt)
	self.addLink(napt,sw5)
	self.addLink(sw5,h3)
	self.addLink(sw5,h4)

#topos = { 'mytopo': ( lambda: MyTopo() ) }

def Phase2():
    c0 = RemoteController('c0', ip='127.0.0.1', port=6633)
    net = Mininet(topo=MyTopo(), controller=c0)
    net.start()

    ds1 = net.get('ds1')
    ds2 = net.get('ds2')
    ds3 = net.get('ds3')
    ws1 = net.get('ws1')
    ws2 = net.get('ws2')
    ws3 = net.get('ws3')
    insp = net.get('insp')

    ds1.cmd('python dns1.py &')
    ds2.cmd('python dns2.py &')
    ds3.cmd('python dns3.py &')
    ws1.cmd('python -m SimpleHTTPServer 80 &')
    ws2.cmd('python -m SimpleHTTPServer 80 &')
    ws3.cmd('python -m SimpleHTTPServer 80 &')

    #CLI(net)
    test(net)
    net.stop()

def test(net):
    log = open(PHASE1_LOG, 'w+') 

    h1 = net.get('h1')
    h2 = net.get('h2')
    h3 = net.get('h3')
    h4 = net.get('h4')
    ds1 = net.get('ds1')
    ds2 = net.get('ds2')
    ds3 = net.get('ds3')
    ws1 = net.get('ws1')
    ws2 = net.get('ws2')
    ws3 = net.get('ws3')
    insp = net.get('insp')

    insp.cmd("tcpdump -s 0 -i insp-eth0 -w ~/ik2220-assign-phase2-team6/results/insp.pcap &")

    #1 h1 icmp h3
    result=h1.cmdPrint('ping -c1', h3.IP())
    log.write('===Case 1. h1 ping h3===\n'+result+'\n\n')

    #2 h3 icmp h1
    result=h3.cmdPrint('ping -c1', h1.IP())
    log.write('===Case 2. h3 ping h1===\n'+result+'\n\n')
	
    #3 h1 icmp ds1
    result=h1.cmdPrint('ping -c1', ds1.IP())
    log.write('===Case 3. h1 ping ds1===\n'+result+'\n\n')
	
    #4 h2 icmp ws1
    result=h2.cmdPrint('ping -c1', ws1.IP())
    log.write('===Case 4. h2 ping ws1===\n'+result+'\n\n')
	
    #5 h3 icmp ds2
    result=h3.cmdPrint('ping -c1', ds2.IP())
    log.write('===Case 5. h3 ping ds2===\n'+result+'\n\n')
	
    #6 h4 icmp ws2
    result=h4.cmdPrint('ping -c1', ws2.IP())
    log.write('===Case 6. h4 ping ws2===\n'+result+'\n\n')

    #7 h1 icmp lb1
    result=h1.cmdPrint('ping -c1 100.0.0.25')
    log.write('===Case 7. h1 ping lb1===\n'+result+'\n\n')

    #8 h3 icmp lb1
    result=h3.cmdPrint('ping -c1 100.0.0.25')
    log.write('===Case 8. h3 ping lb1===\n'+result+'\n\n')
	
    #9 h1 icmp lb2
    result=h1.cmdPrint('ping -c1 100.0.0.45')
    log.write('===Case 9. h1 ping lb2===\n'+result+'\n\n')
	
    #10 h3 icmp lb2
    result=h3.cmdPrint('ping -c1 100.0.0.45')
    log.write('===Case 10. h3 ping lb2===\n'+result+'\n\n')

    #11 h3 TCP ws1
    result=h3.cmdPrint('curl -m 2 ', ws1.IP())
    log.write('===Case 11. h3 curl ws1===\n'+result+'\n\n')

    #12 h1 TCP ws1
    result=h1.cmdPrint('curl -m 2 ', ws1.IP())
    log.write('===Case 12. h1 curl ws1===\n'+result+'\n\n')

    #13 h3 UDP ds1
    dig = ''.join(['dig +time=2 @', ds1.IP(), ' server1.com'])
    result=h3.cmdPrint(dig)
    log.write('===Case 13. h3 dig ds1===\n'+result+'\n\n')
    
    #14 h1 UDP ds1
    dig = ''.join(['dig +time=2 @', ds1.IP(), ' server1.com'])
    result=h1.cmdPrint(dig)
    log.write('===Case 14. h1 dig ds1===\n'+result+'\n\n')
	
    #15 lb test (h3 dig server1)
    dig = ''.join(['dig @100.0.0.25 server1.com'])
    result=h3.cmdPrint(dig)
    log.write('===Case 15. h3 dig lb1===\n'+result+'\n\n')
	
    #16 lb test (h4 dig server2)
    dig = ''.join(['dig @100.0.0.25 server2.com'])
    result=h4.cmdPrint(dig)
    log.write('===Case 16. h4 dig lb1===\n'+result+'\n\n')
	
    #17 lb test (h1 dig server3)
    dig = ''.join(['dig @100.0.0.25 server3.com'])
    result=h1.cmdPrint(dig)
    log.write('===Case 17. h1 dig lb1===\n'+result+'\n\n')
	
    #18 lb test (h2 dig server1)
    dig = ''.join(['dig @100.0.0.25 server1.com'])
    result=h2.cmdPrint(dig)
    log.write('===Case 18. h2 dig lb1===\n'+result+'\n\n')
	
    #19 IDS test (h1 POST test)
    result = h1.cmdPrint('curl 100.0.0.45 -X POST')
    log.write('===Case 19. h1 POST test===\n'+result+'\n\n')
	
    #20 IDS test (h2 PUT test)
    result = h2.cmdPrint('curl 100.0.0.45 -X PUT')
    log.write('===Case 20. h2 PUT test===\n'+result+'\n\n')
	
    #21 IDS test (h3 GET test)
    result = h3.cmdPrint('curl -m 2 100.0.0.45 -X GET')
    log.write('===Case 21. h3 GET test===\n'+result+'\n\n')
	
    #22 IDS test (h4 HEAD test)
    result = h4.cmdPrint('curl -m 2 HEAD 100.0.0.45')
    log.write('===Case 22. h4 HEAD test===\n'+result+'\n\n')
	
    #23 IDS test (h1 OPTION test)
    result = h1.cmdPrint('curl -m 2 OPTION 100.0.0.45')
    log.write('===Case 23. h1 OPTION test===\n'+result+'\n\n')
	
    #24 IDS test (h2 TRACE test)
    result = h2.cmdPrint('curl -m 2 -v -X TRACE 100.0.0.45')
    log.write('===Case 24. h2 TRACE test===\n'+result+'\n\n')
	
    #25 IDS test (h3 DELETE test)
    result = h3.cmdPrint('curl -m 2 DELETE 100.0.0.45')
    log.write('===Case 25. h3 DELETE test===\n'+result+'\n\n')
	
    #26 IDS test (h4 CONNECT test)
    result = h4.cmdPrint('curl -m 2 CONNECT 100.0.0.45')
    log.write('===Case 26. h4 CONNECT test===\n'+result+'\n\n')
	
    #27 IDS test (h1 /etc/passwd test)
    result = h1.cmdPrint('curl -m 2 100.0.0.45 -X PUT -d "cat /etc/passwd"')
    log.write('===Case 27. h1 /etc/passwd test===\n'+result+'\n\n')
	
    #28 IDS test (h2 /var/log/ test)
    result = h2.cmdPrint('curl -m 2 100.0.0.45 -X PUT -d "cat /var/log/"')
    log.write('===Case 28. h2 /var/log/ test===\n'+result+'\n\n')
	
    #29 IDS test (h3 SQL INSERT test)
    result = h3.cmdPrint('curl -m 2 100.0.0.45 -X PUT -d "INSERT"')
    log.write('===Case 29. h3 INSERT test===\n'+result+'\n\n')
	
    #30 IDS test (h4 SQL UPDATE test)
    result = h4.cmdPrint('curl -m 2 100.0.0.45 -X PUT -d "UPDATE"')
    log.write('===Case 30. h4 UPDATE test===\n'+result+'\n\n')
	
    #31 IDS test (h1 SQL DELETE test)
    result = h1.cmdPrint('curl -m 2 100.0.0.45 -X PUT -d "DELETE"')
    log.write('===Case 31. h1 DELETE test===\n'+result+'\n\n')

    log.close()

if __name__ == '__main__':
    setLogLevel('info')
    Phase2()

