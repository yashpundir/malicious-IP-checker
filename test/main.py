
import ipvoid
import virus_total
import pandas as pd


ipvoid.ipvoid()
virus_total.virus_total()

writer = pd.ExcelWriter('D:/malware project/executed.xlsx')
df.to_excel(writer)
writer.save()
