# nmapsearch
Search Nmap XML output files using regular expressions.

# License
Nmapsearch is released under the BSD license. Please see [LICENSE.md](https://github.com/canidorichard/nmapsearch/blob/master/LICENSE.md) for more information.

# Usage
python3 nmapsearch.py [-h] [-f FILE] [-c] [-o {xml,xml_min,ipv4,mac,mac+ipv4}] [-p PATH] -r REGEX

Option | Description
------ | -----------
-h, --help | Show help text  
-f FILE, --file FILE | Specify input file(s)  
-c, --case_sensitive  | Case sensitive search  
-o OUTPUT, --output OUTPUT | Specify output format  
| xml      - Output host record as XML  
| xml_min  - Output the element containing the regex match as XML  
| ipv4     - Output only the IP address of the matching host record  
| mac      - Output the MAC address of the matching host record  
| mac+ipv4 - Output MAC address and IP address 
-p PATH, --path PATH |Specify location of file(s)  
-r REGEX, --regex REGEX | Search expression  
