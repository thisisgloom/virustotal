# virustotal

### **Requires a .env file containing the following key/value pair.**

> VIRUSTOTAL_APIKEY = 'your api key here'


### **HELP**

> usage: virustotal.py [-h] {file,hash,url} -m METHOD DATA
>
>Execute API calls to the VirusTotal API using your own API key stored in .env.
>
>Info: https://github.com/thisisgloom/virustotal<br>
>Python: v3<br>
>Credentials: API key from a registered https://virustotal.com account
>
>
> positional arguments:<br>&emsp;
>   {file,hash,url}  get VirusTotal information about a file, hash, or url
> 
> options:<br>&emsp;
>   -h, --help&emsp;&emsp;&emsp;&nbsp;show this help message and exit<br>&emsp;
>   -m, --method&emsp;&nbsp;&nbsp;flagged: check if flagged by AV vendors<br>
>       &emsp;&emsp;&emsp;&emsp;&emsp;&emsp;&emsp;&emsp;&emsp;comments: returns the top 30 comments<br>
>       &emsp;&emsp;&emsp;&emsp;&emsp;&emsp;&emsp;&emsp;&emsp;votes: return the vote count<br>&emsp;
>   


### **USAGE** 

> .\virustotal.py url httpx://google.com -m flagged


### **REQUIREMENTS** 

> pip install -r requirements.txt