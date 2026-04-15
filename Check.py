'''
[Author]: John Bostater

[Creation Date]: 4/13/26

[Description]: 

	{  WINDOWS OS  }
	
	Perform an automated security audit of networked connections currently running on the user's laptop
	
		Use  [netstat -ano]  &  [curl ipinfo.io/X.X.X.X]		

	[netstat -ano] is only valid with (Windows OS)  [netstat -an]  for (Mac OS)

		
[Key to ipinfo.io JSON dump]

# "ip" 
# "city"
# "region" (State)
# "country" 
# "loc" (Longitude, Latitude) 
# "org" (Organization) 
# "postal" (Postal Code) 
# "timezone" 

			
'''



#[Library Imports]
#---------------
import os
import json
#---------------


#[Global Variables]
#-----------------------------------------------------------

#Compilation of all Foreign IP adddresses & their connection
foreignIPConnections = {}


#OS type	[Unix: False]  [Windows: True]
osType = True if os.name == 'nt' else False

#-----------------------------------------------------------


#TEST!!
#Command 
os.system(f'tasklist > TaskList.txt')


#Yes, I know this is hacky & I should use subprocess instead, I just don't care for this lol
with open('TaskList.txt', 'r') as taskFile:



	#Gather the
	i = 0

	#Print the Third Line onlt
	for line in taskFile:


		if i == 3:
			
			print(line)

			break


		i += 1

	#PLACEHOLDER!!!






#[Functions]
#-----------------------------------------------------------

#Print the reulst of the file (if it exists)
def PrintResults():


	#See if the file exists first
	if(os.path.exists("Results.txt")):
		
		#Open the file & read it's contents
		with open("Results.txt", "r") as file: print(file.read())


	#Else, no results file to process
	else: print('No Results file to process')


#[NEW!!]

#Gather the name of the process via it's PID


#Comment out to implement
#'''


def GetProcessName(pID):
	
	#String containing the process
	processName = f'No [Process Name] Found for _PID_:  {pID}'


	#Command to gather info for the specific PID
	os.system(f'tasklist /FI "PID eq {pID}" > TaskList.txt')
	
	
	#Yes, I know this is hacky & I should use subprocess instead, I just don't care for this lol
	with open('TaskList.txt', 'r') as taskFile:

		#Gather the Third line only as it contains the Name & Size		

		#Track iterations
		i = 0

		#Parse file
		for line in taskFile:

			#Condition met
			if i == 3:
			
				#Process Name (first item)
				processName = line.split()[0]


#[TO DO!!]
				#Process Size
				#	[CODE HERE!!]
				#processSize = line.split()[4]


				#End read here
				break

			#Increment
			i += 1



	#Clean up the file
	os.remove('TaskList.txt')


	#Return the name
	return processName

	
#'''


#-----------------------------------------------------------



'''
[TO DO]:

	- Add a functionality to end the processes of certain connections? (do this via the PID)

	- Pull all users & tasks running too?
	
	- Add handling here if a Results.txt already exists & if the user would like to create a new one or read the existing one
	
	- Add support for Mac OS (should be super simple?)

	- Use the COmmand [tasklist] to track processes and via their PID
		
		[TO SEARCH A SPECIFIC TASK NAME VIA THE PID]
			tasklist /FI "PID eq 1234"
				
'''


#[Program Loop]
#----------------------------------------------------------------------------------------------------------------------------------------------------------


#Loop choice
while True:


	#Prompt the user on how they would like to continue
	userChoice = int(input("\nWhat would you like to do?\n\n0: Log all current connections & print result\n1: Print an existing result\n2: Exit\n\n> "))

	#Choice Handling
	match(userChoice):
		

		#Yes, continue to run commands, collect output, process ip addresses & print their information out
		case 0: 

			#Execute command based on the user's OS type (-ano not available for Unix)
		
			#Run the Netstat command & collect its output to a .txt file (we will parse line-by-line to build a json file of data)
			os.system("netstat -ano > NetStat.txt") if osType else os.system("netstat -an > NetStat.txt")


			#Open the file we just wrote 
			with open('NetStat.txt', 'r') as netStatFile: 
				
				#Parse the .txt file & collect it's information as a Json, prevent duplicates ip addresses! insert IPaddresses as we go
				for parsedLine in netStatFile:
					

					#Process based on connection type, move past connections that make no sense


					#[TCP] Connection
					if "TCP" in parsedLine and not "[::]" in parsedLine:


#[TO DO]
#
# Use the process ID to see what application is running this connection


						#Gather the Local IP address listed in the TCP connection
						localIP = parsedLine.split()[1]

						#Gather the Foreign IP address from the split text
						foreignIP = parsedLine.split()[2]

						#Gather the TCP connection State
						connectionState = parsedLine.split()[3]
						

						#[WINDOWS ONLY]
						#-----------------------------------------------

						#Process ID
						processID = ''

						#Gather the PID (Process ID)
						if osType: processID = parsedLine.split()[4]
						#-----------------------------------------------


						#Only continue if we pass these checks
						if not "0.0.0.0" in foreignIP and not "127.0.0.1" in foreignIP and not foreignIP in foreignIPConnections:


							#{CURL COMMAND}
							# Search up the foreign address and write the result to a json
							os.system(f"curl -s ipinfo.io/{foreignIP.split(':')[0]} > IPinfo.json")

							#Open and process the output to collect as JSON format
							with open('IPinfo.json', 'r') as jsonFile:

								#Process the JSON data
								jsonDump = json.load(jsonFile)


								#[Reference Key to ipinfo.io JSON dump]

								#[Windows Write]	(Includes PID & task information)
								if osType:

									#Write to the Dict
									try: foreignIPConnections[f'{foreignIP}'] = ["TCP", jsonDump["ip"], jsonDump["country"], jsonDump["region"], jsonDump["city"], jsonDump["org"], jsonDump["loc"], processID, GetProcessName(processID)]

									#[ERROR HANDLING]
									except: pass
									
								#[Unix write]
								else:
									
									#Write to the Dict
									try: foreignIPConnections[f'{foreignIP}'] = ["TCP", jsonDump["ip"], jsonDump["country"], jsonDump["region"], jsonDump["city"], jsonDump["org"], jsonDump["loc"]]

									#[ERROR HANDLING]
									except: pass
							
	
							#Comment back in for a one instance call
							#break



					#[UDP] Connection
					elif "UDP" in parsedLine and not "[::]" in parsedLine and not "*:*" in parsedLine and not "[::1]" in parsedLine:


						#Gather the Local IP address listed in the TCP connection
						localIP = parsedLine.split()[1]

						#Gather the Foreign IP address from the split text
						foreignIP = parsedLine.split()[2]


						#Gather the PID (Process ID)
						processID = parsedLine.split()[3]
						

						#Only continue if we pass these checks
						if not "0.0.0.0" in foreignIP and not "127.0.0.1" in foreignIP and not foreignIP in foreignIPConnections:

							#{CURL COMMAND}
							# Search up the foreign address and write the result to a json
							os.system(f"curl -s ipinfo.io/{foreignIP.split(':')[0]} > IPinfo.json")

							#Open and process the output to collect as JSON format
							with open('IPinfo.json', 'r') as jsonFile:

								#Process the JSON data
								jsonDump = json.load(jsonFile)


								#[Reference Key to ipinfo.io JSON dump]

								#Make an entry in the Dictionary 
								
								#[Windows Write]	(Includes PID & task information)
								if osType:

									#Write to the Dict
									try: foreignIPConnections[f'{foreignIP}'] = ["UDP", jsonDump["ip"], jsonDump["country"], jsonDump["region"], jsonDump["city"], jsonDump["org"], jsonDump["loc"], processID, GetProcessName(processID)]

									#[ERROR HANDLING]
									except: pass
									

								#[Unix write]
								else:
									
									#Write to the Dict
									try: foreignIPConnections[f'{foreignIP}'] = ["UDP", jsonDump["ip"], jsonDump["country"], jsonDump["region"], jsonDump["city"], jsonDump["org"], jsonDump["loc"]]

									#[ERROR HANDLING]
									except: pass


							#Comment back in for a one instance call
							#break


#[NEW!!]
			#Clean up all of the files we are done with
			os.remove('IPInfo.json')
			os.remove('NetStat.txt')


			#Write the content to a file
			with open("Results.txt", "w") as file:


				#Process the foreignIP connections line-by-line
				for ipConnection in foreignIPConnections:


					#[Foreign Address]
					file.write(f'\n[Foreign IP]: {foreignIPConnections[ipConnection][1]}\t\n[Protocol]: {foreignIPConnections[ipConnection][0]}\n')
					file.write(f'[Organization]: {foreignIPConnections[ipConnection][5]}\n')


					#[LOCATION INFORMATION]
					#==================================================================================
					file.write('\n\t{Location Information}\n')

					#[Country]
					file.write(f'\n\t\t[Country]: {foreignIPConnections[ipConnection][2]}\n')

					#[Region] (State)
					file.write(f'\t\t[Region]: {foreignIPConnections[ipConnection][3]}\n')

					#[Region] (State)
					file.write(f'\t\t[City]: {foreignIPConnections[ipConnection][4]}\n')

					#[Coordinates] 
					file.write(f'\t\t[Coordinates]: {foreignIPConnections[ipConnection][6]}\n\n')
					#==================================================================================


					#[Task Information (Windows OS only)]
					#==================================================================================

					#Windows only check
					if osType:
						
						#Title text
						file.write('\n\t{Process Information}\n')

						#Process Name
						file.write(f'\n\t\t[Process Name]: {foreignIPConnections[ipConnection][8]}\n')

						#PID
						file.write(f'\t\t[PID]: {foreignIPConnections[ipConnection][7]}\n\n\n')
					

					#==================================================================================

			#Call upon the method for printing results
			PrintResults()



		#Print an existing dump
		case 1: PrintResults()


		#No, Reprompt the user
		case 2: 

			#Exit Statement
			print('Goodbye') 

			#Exit the program
			break

#----------------------------------------------------------------------------------------------------------------------------------------------------------