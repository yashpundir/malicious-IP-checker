 

# Scraping ipvoid
url = "https://www.ipvoid.com/ip-blacklist-check/"
session = requests.Session()
for ip in range(len(df.index)):
	current_ip = df.loc[ip,'IP'].strip()

	try:
	    pay_load = {"ip": current_ip}
	    request = session.post(url, data=pay_load)
	    soup = bfs(request.content, "html5lib")
	  	
	  	# print('configuring out {}'.format(df.loc[ip,'IP']))

	    if len(soup.select('span.label.label-danger'))!=0:
	        result = soup.select('span.label.label-danger')[0].get_text()
	    elif len(soup.select('span.label.label-warning'))!=0:
	        result = soup.select('span.label.label-warning')[0].get_text()
	    else:
	        result = soup.select('span.label.label-success')[-1].get_text()
	    
	    df.loc[ip,'IPVOID'] = result

	except:
		df.loc[ip,'IPVOID'] = 'NA'

	time.sleep(10)
