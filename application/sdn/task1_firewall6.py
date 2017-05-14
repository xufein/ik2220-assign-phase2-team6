from pox.core import core
from pox.forwarding.l2_learning import LearningSwitch
import pox.openflow.libopenflow_01 as of
import pox.lib.packet as pkt

log = core.getLogger()

class task1_FireWall6 (LearningSwitch):
	def __init__ (self, connection):
		LearningSwitch.__init__(self, connection, False)
		
	def _handle_PacketIn (self, event):
		ethPacket = event.parsed

		# drop function same as l2_learning
		def drop (duration = None):
			if duration is not None:
				if not isinstance(duration, tuple):
					duration = (duration,duration)
				msg = of.ofp_flow_mod()
				msg.match = of.ofp_match.from_packet(packet)
				msg.idle_timeout = duration[0]
				msg.hard_timeout = duration[1]
				msg.buffer_id = event.ofp.buffer_id
				self.connection.send(msg)
			elif event.ofp.buffer_id is not None:
				msg = of.ofp_packet_out()
				msg.buffer_id = event.ofp.buffer_id
				msg.in_port = event.port
				self.connection.send(msg)

		# firewall in port 1 (PbZ to DmZ)
		if event.port == 1:
			if ethPacket.find("arp"):
				a = ethPacket.find("arp")
				if a.opcode == a.REPLY or a.opcode == a.REQUEST:
					super(task1_FireWall6, self)._handle_PacketIn(event)
					return
			
			if ethPacket.find("icmp"):
				a = ethPacket.find("icmp")
				if a.type == 0 or a.type == 8:
					super(task1_FireWall6, self)._handle_PacketIn(event)
					return

			if ethPacket.find("tcp"):
				super(task1_FireWall6, self)._handle_PacketIn(event)
				return
					
			if ethPacket.find("udp"):
				if ethPacket.payload.dstip == '100.0.0.51' or ethPacket.payload.dstip == '100.0.0.52':
					drop()
				else:
					super(task1_FireWall6, self)._handle_PacketIn(event)
					return

			else:
				drop()
			return
		
		# firewall in port 2 (DmZ to PbZ)	
		elif event.port == 2:
			if ethPacket.find("arp"):
				a = ethPacket.find("arp")
				if a.opcode == a.REPLY or a.opcode == a.REQUEST:
					super(task1_FireWall6, self)._handle_PacketIn(event)
					return

			if ethPacket.find("icmp"):
				a = ethPacket.find("icmp")
				if a.type == 0 or a.type == 8:
					super(task1_FireWall6, self)._handle_PacketIn(event)
					return

			if ethPacket.find("udp"):
				super(task1_FireWall6, self)._handle_PacketIn(event)
				return

			if ethPacket.find("tcp"):
				super(task1_FireWall6, self)._handle_PacketIn(event)
				return

			else:
				drop()
			return
			
		else:
			drop()
