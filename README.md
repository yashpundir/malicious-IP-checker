# malware-project
## malicious IP address checker
The script checks whether an IP address is declared blacklisted or safe from 3 major security websites, namely:
1. Cisco Talos
2. Virus Total
3. IPVoid

Also maintains a basic log file.

INPUT : 
Excel sheet with IP addresses in a column and 3 empty columns named 'IPVOID','CISCO TALOS', 'VIRUS TOTAL'

OUTPUT:
New excel sheet with the verdict of each IP address from the 3 security tools/websites mentioned above.

### NOTE:
Cisco Talos not working currently. Will fix soon.
