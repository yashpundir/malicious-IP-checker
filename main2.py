import requests
from bs4 import BeautifulSoup as bfs
import time
import pandas as pd
import datetime  
import re 

#USER INPUTS
# input_path = input('Enter the path of the input file:\n')
# input_sheet = input('\nName of the Sheet in Excel file where the IP addresses are stored:\n')
# output_path = input('\nEnter path for where to save the file:\n')


df = pd.read_excel('C:/Users/Public/Documents/malicious IPs/IPs 2lookout.xlsx',sheet_name='Sheet1')
headers = {'User-Agent':'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3'}
log = datetime.datetime.today()

def virus_total():
    for ip in range(len(df.IP)):
        current_ip = df.loc[ip,'IP'].strip()
        print(f"checking ip {df.loc[ip,'IP']} from virus total ({ip+1}/{df.shape[0]})") #for checking purposes

        try:
            url = f"https://www.virustotal.com/ui/ip_addresses/{current_ip}"
            raw = requests.get(url,headers=headers).json()                      #acccessing the response as json
            result_data = raw['data']['attributes']['last_analysis_stats']   #the data I need from the json
            total_checks = sum(result_data.values())
            wmalicious = result_data['malicious']
            
            # Actual result
            if wmalicious==0:
            	result = f"SAFE {wmalicious}/{total_checks}"
            elif 0<wmalicious<=3:
            	result = f"UNSAFE {wmalicious}/{total_checks}"
            else:
            	result = f"BLACKLISTED {wmalicious}/{total_checks}"

            # Adding the final result to the database
            df.loc[ip,'VIRUS TOTAL'] = result
        
        except:
            df.loc[ip,'VIRUS TOTAL'] = "NA"

        print(result)  #for checking purposes
        time.sleep(8)


def ipvoid():
	url = "https://www.ipvoid.com/ip-blacklist-check/"
	session = requests.Session()
	for ip in range(len(df.IP)):
		current_ip = df.loc[ip,'IP'].strip()
		print(f"checking IP {df.loc[ip,'IP']} from ipvoid ({ip+1}/{df.shape[0]})")    # for checking purposes

		try:
		    pay_load = {"ip": current_ip}
		    request = session.post(url, data=pay_load)
		    soup = bfs(request.content, "lxml")

		    if len(soup.select('span.label.label-danger'))!=0:
		        wmalicious = soup.select('span.label.label-danger')[0].get_text()
		    elif len(soup.select('span.label.label-warning'))!=0:
		        wmalicious = soup.select('span.label.label-warning')[0].get_text()
		    else:
		        wmalicious = soup.select('span.label.label-success')[-1].get_text()
		    
		    # Actual result
		    nums = re.findall(r'\d+',wmalicious)
		    if int(nums[0])==0:
		    	result = f"SAFE {nums[0]}/{nums[1]}"
		    elif 0<int(nums[0])<=3:
		    	result = f"UNSAFE {nums[0]}/{nums[1]}"
		    else:
		    	result = f"BLACKLISTED {nums[0]}/{nums[1]}"

		    # Adding the final result to the database
		    df.loc[ip,'IPVOID'] = result

		except:
			df.loc[ip,'IPVOID'] = 'NA'

		print(result)                                                        #for checking purposes
		time.sleep(8)

try:
	ipvoid()
	virus_total()

	writer = pd.ExcelWriter('C:/Users/Public/Documents/malicious IPs/IP scan report.xlsx')
	df.to_excel(writer)
	writer.save()	

	with open('C:/Users/Public/Documents/malicious IPs/log.txt','a') as file:
	    file.write("--------------------------\n")
	    file.write("Script execution : SUCCESS\n")
	    file.write(f"DATE : {log.date()}\n")
	    file.write(f"TIME : {log.time()}\n")
	    file.write(f"Total IPs checked : {len(df.IP)}\n")
	    file.write("--------------------------\n\n")

except:
	with open('C:/Users/Public/Documents/malicious IPs/log.txt','a') as file:
	    file.write("--------------------------\n")
	    file.write("Script execution : FAILED\n")
	    file.write(f"DATE : {log.date()}\n")
	    file.write(f"TIME : {log.time()}\n")
	    file.write("--------------------------\n\n")	

