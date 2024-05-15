# AS-TI-IP-Watchlist
Author: Deepak Kumar Ray 

For any technical questions, please contact me on [Twitter](https://twitter.com/roydeepakku) or [Linkedln](https://www.linkedin.com/in/deepak2/).

This Playbook is created to automatically fetch IP from the threat Intel sites mentioned [here](https://github.com/Bert-JanP/Open-Source-Threat-Intel-Feeds) and Update Into the Sentinel Watchlist.
Please note that there is a watchlist limitation of 10 million active [Items](https://learn.microsoft.com/en-us/azure/sentinel/sentinel-service-limits#watchlist-limits) so you need to delete Old IOC when it crosses the limit.


## Requirements

The following items are required under the template settings during deployment: 

1. Create a watchlist and Provide an Alias/Description for the same.
2. Upload a CSV file with one dummy IP (later remove It), Make sure the field Name is "IP" In the CSV File because the same field is hardcoded in the KQL.
3. Run the Playbook to upload the IOC (IP) to the watchlist.

![image](https://github.com/deepakray184/Sentinel-Playbooks/assets/22987796/f2d3c002-7790-4205-a163-b468ecbe39bd)


## KQL Query

Use the below KQL Query to fetch details, This will get updated with new TI Feeds.


```python
let MISPFeed1 = externaldata(DestIP: string)[@"https://raw.githubusercontent.com/stamparm/ipsum/master/levels/7.txt"] with (format="txt", ignoreFirstRecord=True);
let MISPFeed2 = externaldata(DestIP: string)[@"https://raw.githubusercontent.com/stamparm/ipsum/master/levels/6.txt"] with (format="txt", ignoreFirstRecord=True);
let MISPFeed3 = externaldata(DestIP: string)[@"https://raw.githubusercontent.com/stamparm/ipsum/master/levels/8.txt"] with (format="txt", ignoreFirstRecord=True);
let MiraiFeed = externaldata(DestIP: string)[@"https://mirai.security.gives/data/ip_list.txt"] with (format="txt", ignoreFirstRecord=True);
let ProofPointFeed = externaldata(DestIP: string)[@"https://rules.emergingthreats.net/blockrules/compromised-ips.txt"] with (format="txt", ignoreFirstRecord=True);
let FeodoFeed = externaldata(DestIP: string)[@"https://feodotracker.abuse.ch/downloads/ipblocklist.csv"] with (format="txt", ignoreFirstRecord=True);
let DiamondFoxFeed = externaldata(DestIP: string)[@"https://raw.githubusercontent.com/pan-unit42/iocs/master/diamondfox/diamondfox_panels.txt"] with (format="txt", ignoreFirstRecord=True);
let CINFeed = externaldata(DestIP: string)[@"https://cinsscore.com/list/ci-badguys.txt"] with (format="txt", ignoreFirstRecord=True);
let blocklistdeFeed = externaldata(DestIP: string)[@"https://lists.blocklist.de/lists/all.txt"] with (format="txt", ignoreFirstRecord=True);
let C2IntelFeeds = externaldata(DestIP: string, ioc: string)[@"https://raw.githubusercontent.com/drb-ra/C2IntelFeeds/master/feeds/IPC2s-30day.csv"] with (format="csv", ignoreFirstRecord=True);
let DigitalsideFeed = externaldata(DestIP: string)[@"https://osint.digitalside.it/Threat-Intel/lists/latestips.txt"] with (format="txt", ignoreFirstRecord=True);
let MontySecurityFeed = externaldata(DestIP: string)[@"https://raw.githubusercontent.com/montysecurity/C2-Tracker/main/data/all.txt"] with (format="txt", ignoreFirstRecord=True);
let IPRegex = '[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}';
let MaliciousIP1 = materialize (
    MISPFeed1 
    | where DestIP matches regex IPRegex
    | distinct DestIP
    );
let MaliciousIP2 = materialize (
    MISPFeed2 
    | where DestIP matches regex IPRegex
    | distinct DestIP
    );
let MaliciousIP3 = materialize (
    MISPFeed3 
    | where DestIP matches regex IPRegex
    | distinct DestIP
    );
let MaliciousIP4 = materialize (
    MiraiFeed 
    | where DestIP matches regex IPRegex
    | distinct DestIP
    );
let MaliciousIP5 = materialize (
    ProofPointFeed 
    | where DestIP matches regex IPRegex
    | distinct DestIP
    );
let MaliciousIP6 = materialize (
    FeodoFeed 
    | extend DestIP = extract(IPRegex, 0, DestIP)
    | where isnotempty(DestIP)
    | distinct DestIP
    );
let MaliciousIP7 = materialize (
    DiamondFoxFeed 
    | extend DestIP = extract(@'//(.*?)/', 1, DestIP)
    | extend DestIPToLower = tolower(DestIP)
    | where DestIPToLower matches regex IPRegex
    | distinct DestIP
    );
let MaliciousIP8 = materialize (
    CINFeed 
    | where DestIP matches regex IPRegex
    | distinct DestIP
    );
let MaliciousIP9 = materialize (
    blocklistdeFeed 
    | where DestIP matches regex IPRegex
    | distinct DestIP
    );
let MaliciousIP10 = C2IntelFeeds
    | project DestIP;
let MaliciousIP11 = materialize (
    DigitalsideFeed
    | where DestIP matches regex IPRegex
    | distinct DestIP
    );
let MaliciousIP12 = materialize (
    MontySecurityFeed
    | where DestIP matches regex IPRegex
    | distinct DestIP
    );
union MaliciousIP1, MaliciousIP2, MaliciousIP3, MaliciousIP4, MaliciousIP5, MaliciousIP6, MaliciousIP7, MaliciousIP8, MaliciousIP9, MaliciousIP10, MaliciousIP11, MaliciousIP12
| where not(ipv4_is_private( DestIP))
| extend IP = DestIP
| project IP
```

## Output

Once the Playbook starts running, It will automatically add the IOC to the watchlist. This watchlist can be used to correlate against RAW logs of different log sources to generate alerts. 

![image](https://github.com/deepakray184/Sentinel-Playbooks/assets/22987796/4d1120a5-41f7-4059-84bf-d1da5eb5d6fb)


## Reference

[Bert-JanP's TI List](https://github.com/Bert-JanP/Open-Source-Threat-Intel-Feeds)
