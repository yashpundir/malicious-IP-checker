import pandas as pd 
import requests
import time
from bs4 import BeautifulSoup as bfs 

#Scraping ipvoid
url = "https://www.ipvoid.com/ip-blacklist-check/"
session = requests.Session()
results = []
for ip in df.IP:
    pay_load = {"ip": ip}
    request = session.post(url, data=pay_load)
    soup = bfs(request.content, "html5lib")
    if len(soup.select('span.label.label-danger'))!=0:
        result = soup.select('span.label.label-danger')[0].get_text()[11:]
    elif len(soup.select('span.label.label-warning'))!=0:
        result = soup.select('span.label.label-warning')[0].get_text()[11:]
    else:
        result = soup.select('span.label.label-success')[-1].get_text()[13:]
    results.append(result)
    # time.sleep(10)

