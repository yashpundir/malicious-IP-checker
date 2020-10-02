import requests
from bs4 import BeautifulSoup as bfs
import time
import pandas as pd  
import datetime

df = pd.read_excel('D:/malware project/IPs 2lookout.xlsx',sheet_name='Sheet1')
headers = {'User-Agent':'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3'}
log = datetime.datetime.today()

def virus_total():
    for ip in range(df.shape[0]):
        current_ip = df.loc[ip,'IP'].strip()
        # print(f"configuring ip {df.loc[ip,'IP']} from virus total ({ip}/{df.shape[0]})") for checking purposes

        try:
            url = f"https://www.virustotal.com/ui/ip_addresses/{current_ip}"
            raw = requests.get(url,headers=headers).json()                      #acccessing the response as json
            result_data = raw['data']['attributes']['last_analysis_stats']   #the data I need from the json
            total_checks = sum(result_data.values())
            wmalicious = result_data['malicious']
            result = f"{wmalicious}/{total_checks}"
            df.loc[ip,'VIRUS TOTAL'] = result
        
        except:
            df.loc[ip,'VIRUS TOTAL'] = "NA"
        # print(result) for checking purposes
        time.sleep(10)


def ipvoid():
	url = "https://www.ipvoid.com/ip-blacklist-check/"
	session = requests.Session()
	for ip in range(df.shape[0]):
		current_ip = df.loc[ip,'IP'].strip()
		# print(f"configuring out IP {df.loc[ip,'IP']} from ipvoid ({ip}/{df.shape[0]})")  for checking purposes

		try:
		    pay_load = {"ip": current_ip}
		    request = session.post(url, data=pay_load)
		    soup = bfs(request.content, "lxml")

		    if len(soup.select('span.label.label-danger'))!=0:
		        result = soup.select('span.label.label-danger')[0].get_text()
		    elif len(soup.select('span.label.label-warning'))!=0:
		        result = soup.select('span.label.label-warning')[0].get_text()
		    else:
		        result = soup.select('span.label.label-success')[-1].get_text()
		    
		    df.loc[ip,'IPVOID'] = result

		except:
			df.loc[ip,'IPVOID'] = 'NA'
		# print(result) for checking purposes
		time.sleep(10)

try:
	ipvoid()
	virus_total()

	writer = pd.ExcelWriter('D:/malware project/code_test.xlsx')
	df.to_excel(writer)
	writer.save()	

	with open('D:/malware project/log.txt','a') as file:
	    file.write("--------------------------\n")
	    file.write("Script execution : SUCCESS")
	    file.write(f"DATE : {log.date()}\n")
	    file.write(f"TIME : {log.time()}\n")
	    file.write("--------------------------\n\n")

except:
	with open('D:/malware project/log.txt','a') as file:
	    file.write("--------------------------\n")
	    file.write("Script execution : FAILED")
	    file.write(f"DATE : {log.date()}\n")
	    file.write(f"TIME : {log.time()}\n")
	    file.write("--------------------------\n\n")	

