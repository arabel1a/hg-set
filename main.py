#!/usr/bin/env python3
#
# Simple pyprofibus dummy example using dummy PHY.
# This example can be run without any PB hardware.
#

import pyprofibus
import sys
from threading import Thread
#from serial import Exceptions
outData = {}
inData = {}
rem_in_data = {}
myData = {}

myData2 = [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 
			0x00, 0x00, 0x00, 0x00]
myData3 = [0xAA, 0xAA, 0xAA, 0xAA]

rem_in_data['siemems'] = [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00,0x00, 0x00, 0x00]
rem_in_data['bosh'] = [0xAA, 0xAA, 0xAA, 0xAA]

myData['siemems'] = myData2
myData['bosh'] = myData3

myTemplate = "SAddr | Siemens O | Siemens I | BAddr     | Bosh \n" \
		   "  1   |    {}   |   {}    |  2-1  (i) |  {} \n" \
		   "  2   |    {}   |   {}    |  2-2  (i) |  {} \n" \
		   "  5   |    {}   |   {}    |  2-3  (i) |  {}  \n" \
		   "  7   |    {}   |   {}    |  2-4  (i) |  {} \n" \
		   "  8   |    {}   |   {}    |  3-1  (i) |  {} \n" \
		   "  9   |    {}   |   {}    |  3-2  (i) |  {} \n" \
		   "  10  |    {}   |   {}    |  4-1  (o) |  {} \n" \
		   "  13  |    {}   |   {}    |  4-2  (o) |  {} \n"\
		   "  --  |    ----   |   ----    |  5-1  (o) |  {}\n"\
		   "  --  |    ----   |   ----    |  5-2  (o) |  {}\n"


def kek(watchdog=None):
	master = None
	try:
		# Parse the config file.54
		config = pyprofibus.PbConf.fromFile("main.conf")

		# Create a DP master.
		master = config.makeDPM()

		# Create the slave descriptions.

		for slaveConf in config.slaveConfs:
			slaveDesc = slaveConf.makeDpSlaveDesc()

			# Set User_Prm_Data
			dp1PrmMask = bytearray((pyprofibus.dp.DpTelegram_SetPrm_Req.DPV1PRM0_FAILSAFE,
						pyprofibus.dp.DpTelegram_SetPrm_Req.DPV1PRM1_REDCFG,
						0x00))
			dp1PrmSet  = bytearray((pyprofibus.dp.DpTelegram_SetPrm_Req.DPV1PRM0_FAILSAFE,
						pyprofibus.dp.DpTelegram_SetPrm_Req.DPV1PRM1_REDCFG,
						0x00))
			#slaveDesc.setUserPrmData(slaveConf.gsd.getUserPrmData(dp1PrmMask=dp1PrmMask,
									#    dp1PrmSet=dp1PrmSet))


			# Register the slave at the DPM
			master.addSlave(slaveDesc)

			# Set initial output data.
			outData[slaveDesc.name] = myData[slaveDesc.name]
			# print(slaveDesc.name)

		# Initialize the DPM
		master.initialize()
		# Run the slave state machine.
		while True:
			# Write the output data.
			for slaveDesc in master.getSlaveList():
				slaveDesc.setOutData(bytearray(outData[slaveDesc.name]))
			# Run slave state machines.
			handledSlaveDesc = master.run()

			# Get the in-data (receive)
			if handledSlaveDesc:
				inData[handledSlaveDesc.name] = handledSlaveDesc.getInData()
				if inData[handledSlaveDesc.name] is not None:
					rem_in_data[handledSlaveDesc.name] = inData[handledSlaveDesc.name]
			master.syncMode(1)
			# In our example the output data shall be the inverted input.
			# outData[handledSlaveDesc.name][0] = inData[1]
			# outData[handledSlaveDesc.name][1] = inData[0]

			# Feed the system watchdog, if it is available.
			#

			#print('kek')
			if watchdog is not None:
				watchdog()
	except pyprofibus.ProfibusError as e:
		print("Terminating: %s" % str(e))
		return 1
	finally:
		if master:
			master.destroy()
	return 0

def main():
	Thread(target=kek).start();
	while True:
		s = input().split(' ')
		print("\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n")
		#usage: [sb] [addr] [bitnum]
		if len(s) > 0 and s[0] == 's':
			try:
				if(len(s[2]) == 1 and int(s[2]) >= 0 and int(s[2]) <= 3):
					myData['siemems'][int(s[1]) // 2] = myData['siemems'][int(s[1]) // 2] ^ 1 << (int(s[2]) + 4*((int(s[1]) + 1) % 2))
				else:
					if( len(s[2]) == 4):
						myData['siemems'][int(s[1]) // 2] =  (myData['siemems'][int(s[1]) // 2] & (int('1111',2) << (4 * ((int(s[1]) ) % 2) ))) | (int(s[2], 2) << (4 * ((int(s[1]) + 1) % 2))) #int(s[2], 2)
				# print([hex(i) for i in myData['siemems']])
			except Exception as ee:
				continue

		if len(s) > 0 and s[0] == 'b':
			try:
				dct = {"4-1" : 0, "4-2" : 1, "5-1" : 2, "5-2" : 3,}
				if s[1] in dct.keys():
					byten = dct[s[1]]
					if len(s[2]) == 1:
						myData['bosh'][byten] = myData['bosh'][byten] ^ 1 << int(s[2])
					else:
						myData['bosh'][byten] = int(s[2],2)
			except Exception as  eb:
				continue
		try:
			print(myTemplate.format(str(bin(myData['siemems'][0] % 16))[2:].zfill(4), str(bin(rem_in_data['siemems'][0] % 16))[2:].zfill(4),
								str(bin(rem_in_data['bosh'][0]))[2:].zfill(8),
								str(bin(myData['siemems'][1] // 16))[2:].zfill(4), str(bin(rem_in_data['siemems'][1] // 16))[2:].zfill(4),
								str(bin(rem_in_data['bosh'][1]))[2:].zfill(8),
								str(bin(myData['siemems'][2] % 16))[2:].zfill(4), str(bin(rem_in_data['siemems'][2] % 16))[2:].zfill(4),
								str(bin(rem_in_data['bosh'][2]))[2:].zfill(8),
								str(bin(myData['siemems'][3] % 16))[2:].zfill(4), "----",# str(bin(rem_in_data['siemems'][3] % 16))[2:].zfill(4),
								str(bin(rem_in_data['bosh'][3]))[2:].zfill(8),
								str(bin(myData['siemems'][4] // 16))[2:].zfill(4), "----",#str(bin(rem_in_data['siemems'][4] // 16))[2:].zfill(4),
								str(bin(rem_in_data['bosh'][4]))[2:].zfill(8),
								str(bin(myData['siemems'][4] % 16))[2:].zfill(4), "----",#str(bin(rem_in_data['siemems'][4] % 16))[2:].zfill(4),
								str(bin(rem_in_data['bosh'][5]))[2:].zfill(8),
								str(bin(myData['siemems'][5] // 16))[2:].zfill(4), str(bin(rem_in_data['siemems'][5] // 16))[2:].zfill(4),
								str(bin(myData['bosh'][0]))[2:].zfill(8),
								str(bin(myData['siemems'][6] % 16))[2:].zfill(4), str(bin(rem_in_data['siemems'][6] % 16))[2:].zfill(4),
								str(bin(myData['bosh'][1]))[2:].zfill(8),
								str(bin(myData['bosh'][2]))[2:].zfill(8),
								str(bin(myData['bosh'][3]))[2:].zfill(8),))
		except Exception as e:
			continue

if __name__ == "__main__":
	sys.exit(main())

