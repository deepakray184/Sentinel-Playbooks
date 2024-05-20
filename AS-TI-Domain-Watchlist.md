# AS-TI-Hash-Watchlist
Author: Deepak Kumar Ray 

For any technical questions, please contact me on [Twitter](https://twitter.com/roydeepakku) or [Linkedln](https://www.linkedin.com/in/deepak2/).

This Playbook is created to automatically fetch IP from the threat Intel sites mentioned [here](https://github.com/deepakray184/Sentinel-Playbooks/blob/main/README.md) and Update Into the Sentinel Watchlist.
Please note that there is a watchlist limitation of 10 million active [Items](https://learn.microsoft.com/en-us/azure/sentinel/sentinel-service-limits#watchlist-limits) so you need to delete Old IOC when it crosses the limit.

[![Deploy to Azure](https://aka.ms/deploytoazurebutton)]()


## Requirements

The following items are required under the template settings during deployment: 

1. Create a watchlist and Provide an Alias/Description for the same.
2. Upload a CSV file with one dummy IP (later remove It), Make sure the field Name is "IP" In the CSV File because the same field is hardcoded in the KQL.
3. Run the Playbook to upload the IOC (IP) to the watchlist.

![image](https://github.com/deepakray184/Sentinel-Playbooks/assets/22987796/f2d3c002-7790-4205-a163-b468ecbe39bd)


## KQL Query

Use the below KQL Query to fetch details, This will get updated with new TI Feeds.


```python
TBD
```

## Output

Once the Playbook starts running, It will automatically add the IOC to the watchlist. This watchlist can be used to correlate against RAW logs of different log sources to generate alerts. 


## Usage

Utilize It with different Sentinel Tables which consist of Fieldname as IP address. Use the below query to check if there are any Intel IP matches In the CommonSecurityLog Table.

```bash
let TI_Hash = _GetWatchlist('External_IOC')
| project IP;
CommonSecurityLog
| where SourceIP in (TI_Hash)
```

## Reference

[Bert-JanP's TI List](https://github.com/Bert-JanP/Open-Source-Threat-Intel-Feeds)

