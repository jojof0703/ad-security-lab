# AD Security Lab
A self-built, deliberately-vulnerable Active Directory environment, designed, attacked, detected, and remediated end to end, in the style of GOAD/DetectionLab rather than a blind pentest. The goal wasn't just to find vulnerabilities, but to build the whole lifecycle. I wanted to plant realistic misconfigurations, discover and exploit them from an attacker's position, catch them happening with a real SIEM pipeline, and fix them with proof the fix actually holds. 


## Structure
- [01 - Lab Environment](01-environment.md) - Proxmox host, network isolation, VM inventory
- [02 - Planted Misconfigurations](02-misconfigurations.md) - the five vulnerabilities, planted deliberately as ground truth
- [03 - Enumeration](03-enumeration.md) - attacking the domain blind, from an unprivileged user's position
- [04 - Detection & Logging](04-detection.md) - building a Wazuh SIEM pipeline and a custom Kerberoasting detection rule
- [05 - Remediation](05-remediation.md) - fixing every finding and re-attacking to confirm the fix holds

## Tools

Proxmox VE, Windows Server 2022, Windows 11, Kali Linux, BloodHound CE + Neo4j, Impacket, John the Ripper, Wazuh 4.13.1