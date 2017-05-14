from pox.core import core
from pox.forwarding.l2_learning import LearningSwitch
from task1_firewall6 import task1_FireWall6
from task1_firewall7 import task1_FireWall7
import os

def launch ():
	controller = task_1_controller()
	core.register("controller", controller)

class task_1_controller (object):
	def __init__ (self):
		core.openflow.addListeners(self)

	def _handle_ConnectionUp (self, event):
		dpid = event.dpid

		if dpid == 1 or dpid == 2 or dpid == 3 or dpid == 4 or dpid == 5:
			LearningSwitch(event.connection, False)

		elif dpid == 6:
			task1_FireWall6(event.connection)

		elif dpid == 7:
			task1_FireWall7(event.connection)

		elif dpid == 8:
			os.system('sudo /usr/local/bin/click /home/click/ik2220-assign-phase2-team6/application/nfv/lb1.click &')

		elif dpid == 9:
			os.system('sudo /usr/local/bin/click /home/click/ik2220-assign-phase2-team6/application/nfv/lb2.click &')
			
		elif dpid == 10:
			os.system('sudo /usr/local/bin/click /home/click/ik2220-assign-phase2-team6/application/nfv/ids.click &')

		elif dpid == 11:
			os.system('sudo /usr/local/bin/click /home/click/ik2220-assign-phase2-team6/application/nfv/napt.click &')

