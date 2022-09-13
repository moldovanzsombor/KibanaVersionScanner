# Kibana Version Scanner

Kibana is a free and open user interface that lets you visualize your Elasticsearch data and navigate the Elastic Stack.
Do anything from tracking query load to understanding the way requests flow through your apps.
https://www.elastic.co/kibana/

### Testing

All targets during testing were found on shodan.io:
https://www.shodan.io/

==Do not attack sites without permission==

Shodan dork:
```
port:5601 kibana
```

Search for public kibana vulnerabilities: `https://www.cvedetails.com/google-search-results.php?q=kibana&sa=Search`

Tested on versions:
```
4.X.X  ->  8.4.1
```

### Use

Script is based on https://github.com/LandGrey/CVE-2019-7609 CVE script

```bash
python3 kibanascan.py targets.txt
Target: http://[REDACTED].211:5601/app/kibana
Version: 5.5.2

Target: http://[REDACTED].37:5601/app/kibana
Version: 6.4.3

Target: http://[REDACTED].204:5601/app/kibana
Version: 8.1.0

Target: http://[REDACTED].214:5601/app/kibana
Version: 7.9.3

Target: http://[REDACTED].120:5601/app/kibana
Version: 4.6.2
```

