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
#-----------------------------------------------------------


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

#-----------------------------------------------------------



'''
[TO DO]:

	- Add a functionality to end the processes of certain connections? (do this via the PID)

	- Pull all users & tasks running too?
	
	- Add handling here if a Results.txt already exists & if the user would like to create a new one or read the existing one
	
	- Add support for Mac OS (should be super simple?)

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
			

			#Run the Netstat command & collect its output to a .txt file (we will parse line-by-line to build a json file of data)
			os.system("netstat -ano > NetStat.txt")


			#Open the file we just wrote 
			with open('NetStat.txt', 'r') as netStatFile: 
				
				#Parse the .txt file & collect it's information as a Json, prevent duplicates ip addresses! insert IPaddresses as we go
				for parsedLine in netStatFile:
					

					#Process based on connection type, move past connections that make no sense


					#[TCP] Connection
					if "TCP" in parsedLine and not "[::]" in parsedLine:

						#Gather the Local IP address listed in the TCP connection
						localIP = parsedLine.split()[1]

						#Gather the Foreign IP address from the split text
						foreignIP = parsedLine.split()[2]

						#Gather the TCP connection State
						connectionState = parsedLine.split()[3]
						
						#Gather the PID (Process ID)
						processID = parsedLine.split()[4]


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
								try: foreignIPConnections[f'{foreignIP}'] = ["UDP", jsonDump["ip"], jsonDump["country"], jsonDump["region"], jsonDump["city"], jsonDump["org"], jsonDump["loc"]]
	

								#[ERROR HANDLING]
								except: pass


							#Comment back in for a one instance call
							#break


			#Write the content to a file
			with open("Results.txt", "w") as file:


				#Process the foreignIP connections line-by-line
				for ipConnection in foreignIPConnections:


					#[Foreign Address]
					file.write(f'\n[Foreign IP]: {foreignIPConnections[ipConnection][1]}\n')

					#[Country]
					file.write(f'\n\t[Country]: {foreignIPConnections[ipConnection][2]}\n')

					#[Region] (State)
					file.write(f'\t[Region]: {foreignIPConnections[ipConnection][3]}\n')

					#[Region] (State)
					file.write(f'\t[City]: {foreignIPConnections[ipConnection][4]}\n')

					#[Region] (State)
					file.write(f'\t[Organization]: {foreignIPConnections[ipConnection][5]}\n')

					#[Coordinates] 
					file.write(f'\t[Coordinates]: {foreignIPConnections[ipConnection][6]}\n')


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