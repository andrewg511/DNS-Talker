
import argparse
from sys import argv
import socket
import binascii
import struct

parser=argparse.ArgumentParser(description="""This is a very basic server program""")
parser.add_argument('port', type=int, help='port number', action= 'store')
args = parser.parse_args(argv[1:])


client_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client_sock.bind(('', args.port))
client_sock.listen(0)




conn, addr = client_sock.accept()

##Citation: https://routley.io/posts/hand-writing-dns-messages/
def sendMessage (message, address, port):
	google_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	
	serveraddress = (address, port)
	try:
		google_sock.sendto(binascii.unhexlify(message), serveraddress)
		data, _ = google_sock.recvfrom(4096)
	finally:
		google_sock.close()
	return binascii.hexlify(data).decode("utf-8")
	
firstconnect = True
while firstconnect:
	
	while True:
		
		dnsName = conn.recv(256).decode('utf-8')
		if (not dnsName):
	
			firstconnect = False
			break	
		
		else:
			#Header: AA AA = ID + 0000 0001 0000 0000 = 01 00 in hex = Query Params + 00 01 = questions + 00 00 = answers + 00 00 = authority records + 00 00 = additional records 
			#Question: QNAME = the URL (dnsName). to encode this, we need to turn each charachter into ASCII. + QTYPE = A records value 1 + QCLASS = IN, value 1
			#07 65 - 'example' has length 7, e
			#78 61 - x, a
			#6D 70 - m, p
			#6C 65 - l, e
			#03 63 - 'com' has length 3, c
			#6F 6D - o, m
			#00    - zero byte to end the QNAME
			#00 01 - QTYPE
			#00 01 - QCLASS
			
			dnsHexed = ""
			counter = 0 
			stringLength = len(dnsName)
			
			while True:
				
				if(stringLength == counter):
					break
				else:
					
					if(dnsName[counter] == '.' or counter == 0):
						newCounter = 0
						oldCounter = counter + 1
						
						while(oldCounter < stringLength):
							
							if(dnsName[oldCounter] == '.'):
								break
							else:
								newCounter = newCounter + 1
								oldCounter = oldCounter + 1
						
						
						
						if(counter == 0):
							newCounter = newCounter + 1
							dnsHexed = dnsHexed + "0" + str(newCounter)
							dnsHexed = dnsHexed + binascii.hexlify(dnsName[counter])
						else:
							dnsHexed = dnsHexed + "0" + str(newCounter)
							
						counter = counter + 1
					
					else:
						
						dnsHexed = dnsHexed + binascii.hexlify(dnsName[counter])
						counter = counter + 1
					
			dnsHexed = dnsHexed + "0000010001"
			
			message = "AAAA01000001000000000000" + dnsHexed
			
			
			parttoskip = len(message) + 19 ## this will give us our index to start at

			response = sendMessage(message, "8.8.8.8", 53)
			##hexedrdlength = response[parttoskip+1] + response[parttoskip+2] + response[parttoskip+3] + response[parttoskip+4]
			##parttoskip = parttoskip + 5
			
			responselength = len(response)

			
			
			
		 #what we need to know:
		 #we need a counter to make sure we have passed the loop through 4 hex pairs
		 # 1 byte = 8 bits
	
			
			byteCounter = 0
			answerString = ""
			while(parttoskip < responselength):
				
				hexedrdlength = response[parttoskip+1] + response[parttoskip+2] + response[parttoskip+3] + response[parttoskip+4]
				parttoskip = parttoskip + 5
				
				rdlength = int(hexedrdlength, 16)
				
				if(rdlength != 4):
					answerString = answerString + "IP not found"
				
					parttoskip = parttoskip + rdlength - 2
					
					if(parttoskip + 19 >= responselength and parttoskip >= responselength):
						break
					else:
						parttoskip = parttoskip + 19
				else:
					while(byteCounter < rdlength):
				
						hexString = response[parttoskip] + response[parttoskip+1]
						parttoskip = parttoskip + 2
						intVal = int(hexString, 16)
						if(byteCounter+1 == rdlength):
							answerString = answerString + str(intVal)
						else:
							answerString = answerString + str(intVal) + "."
							
						byteCounter = byteCounter + 1
					
					
				if(parttoskip + 19 >= responselength and parttoskip >= responselength):
					break
				else:
					parttoskip = parttoskip + 19
				
				answerString = answerString + " , "
				byteCounter = 0
			
			conn.send(answerString.encode('utf-8'))
			
	
client_sock.close()
		
		



	

	







