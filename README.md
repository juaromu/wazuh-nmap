**WAZUH AND NMAP FOR NETWORK SCAN**
## 

## Intro

Wazuh and NMAP integration to scan network subnets for open ports and services.

In this integration we’ll use python-nmap (https://pypi.org/project/python-nmap/) to scan for open ports/services found in different subnets.

NMAP port scanners can be installed in different Wazuh agents placed in different network segments. The NMAP output is converted to JSON and appended to each agent’s active responses file.

The scan can be scheduled via chrome job to be executed once a week, month, etc. It can also be triggered using Wazu’s wodle command integration.


## Requirements


* NMAP installed in every agent to run the network scan.
* python-nmap ([https://pypi.org/project/python-nmap/](https://pypi.org/project/python-nmap/)) installed.


## Python-nmap

Python-nmap is a python library which helps in using nmap port scanner. It allows to easilly manipulate nmap scan results and will be a perfect tool for systems administrators who want to automate scanning tasks and reports. It also supports nmap script outputs.


## Python script run on agents


```
################################
### Python Script to Run Network Scans and append results to Wazuh Active Responses Log
### Requirements:
###     NMAP installed in Agent
###     python-nmap (https://pypi.org/project/python-nmap/)
### Replace the Array "subnets" with the subnets to scan from this agent.
### Do NOT include subnets with a network firewall in the path of the agent and the subnet.
################################
import nmap
import time
import json
nm = nmap.PortScanner()
#Add subnets to scan to the Subnets Array
subnets=['192.168.252.0/24','192.168.1.0/24']
for subnet in subnets:
    json_output={}
    nm.scan(subnet)
    for host in nm.all_hosts():
        json_output['nmap_host']=host
        for proto in nm[host].all_protocols():
            if proto not in ["tcp", "udp"]:
                continue
            json_output['nmap_protocol']=proto
            lport = list(nm[host][proto].keys())
            lport.sort()
            for port in lport:
                hostname = ""
                json_output['nmap_port']=port
                for h in nm[host]["hostnames"]:
                    hostname = h["name"]
                    json_output['nmap_hostname']=hostname
                    hostname_type = h["type"]
                    json_output['nmap_hostname_type']=hostname_type
                    json_output['nmap_port_name']=nm[host][proto][port]["name"]
                    json_output['nmap_port_state']=nm[host][proto][port]["state"]
                    json_output['nmap_port_product']=nm[host][proto][port]["product"]
                    json_output['nmap_port_extrainfo']=nm[host][proto][port]["extrainfo"]
                    json_output['nmap_port_reason']=nm[host][proto][port]["reason"]
                    json_output['nmap_port_version']=nm[host][proto][port]["version"]
                    json_output['nmap_port_conf']=nm[host][proto][port]["conf"]
                    json_output['nmap_port_cpe']=nm[host][proto][port]["cpe"]
                    with open("/var/ossec/logs/active-responses.log", "a") as active_response_log:
                        active_response_log.write(json.dumps(json_output))
                        active_response_log.write("\n")
                time.sleep(2)
```


This script can be placed in any folder in the agent’s file system and its execution can be scheduled using cron.


## Detection Rules (Wazuh Manager)


```
<group name="linux,nmap,network_scan">
    <rule id="200400" level="3">
        <decoded_as>json</decoded_as>
        <field name="nmap_host">\.+</field>
        <field name="nmap_protocol">\.+</field>
        <description>NMAP: Network Scan Host $(nmap_host)</description>
        <options>no_full_log</options>
    </rule>
</group>
```



## Scan Results - Wazuh Manager Alerts (examples)


```
{
   "timestamp":"2022-02-23T04:37:32.001+0000",
   "rule":{
      "level":3,
      "description":"NMAP: Network Scan Host 192.168.252.222",
      "id":"200400",
      "firedtimes":55,
      "mail":false,
      "groups":[
         "linux",
         "nmap",
         "netwprk_scan"
      ]
   },
   "agent":{
      "id":"017",
      "name":"ubunutu2004vm",
      "ip":"192.168.252.191"
   },
   "manager":{
      "name":"ASHWZH01"
   },
   "id":"1645591052.115711751",
   "decoder":{
      "name":"json"
   },
   "data":{
      "nmap_host":"192.168.252.222",
      "nmap_protocol":"tcp",
      "nmap_port":"443",
      "nmap_hostname":"_gateway",
      "nmap_hostname_type":"PTR",
      "nmap_port_name":"https",
      "nmap_port_state":"open",
      "nmap_port_product":"OPNsense",
      "nmap_port_reason":"syn-ack",
      "nmap_port_conf":"10"
   },
   "location":"/var/ossec/logs/active-responses.log"
}
```
