'''
[Author]: John Bostater

[Creation Date]: 4/13/26

[Description]: 

	{  WINDOWS OS  } Only!!

	Perform an automated security audit of networked connections currently running on the user's laptop
	
		Use  [netstat -ano]  &  [curl ipinfo.io/X.X.X.X]

'''


#Library Imports
#---------------
import os
#---------------


#Global Variables
#-----------------------------------------------------------


#Compilation of all Foreign IP adddresses & their connection
#	{can help us prevent duplicates, gives us O(1) runtime}
foreignIPConnections = {}


#-----------------------------------------------------------


#Program Loop
while True:

	#Prompt the user on how they would like to continue
	userChoice = int(input("Would you like to continue?\n\n0: Yes\n1: No\n\n> "))

	#Choice Handling
	match(userChoice):
		

		#Yes, continue to run commands, collect output, process ip addresses & print their information out
		case 0: 
			
			#PLACEHOLDER
			#XXXXXXXXXXXXXXXXXXXXX
			print('Hello')
			#XXXXXXXXXXXXXXXXXXXXX


			#Run the Netstat command & collect its output to a .txt file (we will parse line-by-line to build a json file of data)
			os.system("netstat -ano > NetStat.txt")


			#Open the file we just wrote 
			with open('NetStat.txt', 'r') as netStatFile: 
				
				#Parse the .txt file & collect it's information as a Json, prevent duplicates ip addresses! insert IPaddresses as we go
				for parsedLine in netStatFile:
					

					#Process based on connection type


					#[TCP] Connection
					if "TCP" in parsedLine:

						#Gather the Local IP address listed in the TCP connection
						localIP = parsedLine.split()[1]


						#Gather the Foreign IP address from the split text
						foreignIP = parsedLine.split()[2]

						#Gather the State
						connectionState = parsedLine.split()[3]
						

						#Gather the PID (Process ID)
						processID = parsedLine.split()[4]


#[TO DO]:
#	Add a functionality to end the processes of certain connections? (do this via the process Id)




					#[UDP] Connection
					elif "UDP" in parsedLine:
						
						#PLACEHOLDER
						#XXXXXXXXXXX
						print("UDP")
						#XXXXXXXXXXX



		#No, Reprompt the user
		case 1: 

			#Exit Statement
			print('Goodbye') 

			#Exit the program
			break
			