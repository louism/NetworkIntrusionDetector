import os
import io

logs = []
ips= dict() # the dictionary of ips.
times= dict() # the dictionary of timestamps
reportFile = open('report.txt', 'w') #create report.txt for writing

def addRequest(ip, time):

	if ip in ips:
			ips[ip] = ips[ip]+1    # if the word is already in the dictionary, increment its count
	else:
			ips[ip] = 1;		   # set ip's count to 1
			times[ip] = time;	


#find all files with .log extension
for file in os.listdir("."):
	if file.endswith(".log"):
		logs.append(file);



for file in logs:
	f = io.open(file, 'r')  #open the file for reading.
	for line in f:
		dumpline= line.split(' ');

		#check if packet is a SYN packet
		if(len(dumpline) < 2 or dumpline[1]!='IP' or dumpline[6] != '[S],'):
			continue
		src = dumpline[2]
		srcs = src.split('.')
		srcip = srcs[0] + '.' + srcs[1]+'.' + srcs[2]+"."+srcs[3]
		#extract the source ip

		dest = dumpline[4]
		dests = dest.split('.')
		destip = dests[0] + '.' + dests[1]+'.' + dests[2]+"."+dests[3]
		#extract the destination ip

		#add the request
		addRequest(srcip, dumpline[0])

	reportFile.write(file + '\n')
	#write the name of the file to show from which file a scan was found

	for value in ips:   # loop through each value in the dictionary.
		if ips[value]>5: #if ip initiated more than 5 connections
			reportFile.write("Scan from " + value +" at " + times[value]+"\n")
		


	ips.clear();
	times.clear();
	#clear old lists before checking next file.
		
print("result in report.txt")