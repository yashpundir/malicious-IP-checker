import requests
from bs4 import BeautifulSoup as bfs
import time
import pandas as pd  

df = pd.read_excel('D:/malware project/IPs 2lookout.xlsx',sheet_name='Sheet1')

#scraping virus total
def virus_total():
    for ip in range(df.shape[0]):
        # print(f"configuring ip {df.loc[ip,'IP']}")

        current_ip = df.loc[ip,'IP'].strip()

        try:
            url = f"https://www.virustotal.com/ui/ip_addresses/{current_ip}"
            raw = requests.get(url,headers=headers).json()                      #acccessing the response as json
            result_data = raw['data']['attributes']['last_analysis_stats']   #the data I need from the json
            total_checks = sum(result_data.values())
            wmalicious = result_data['malicious']
            df.loc[ip,'VIRUS TOTAL'] = f"{wmalicious}/{total_checks}"
        
        except:
            df.loc[ip,'VIRUS TOTAL'] = "NA"
        
        time.sleep(10)                                                          #time delay so as not to bombard the website with requests
