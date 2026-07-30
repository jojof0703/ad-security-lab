# 01 -- Lab Environment 

## Goal

Build an isolated Active Directory environment that can be deliberately misconfigured, attacked, and then monitored - without exposing a vulnerable domain to the home network or the internet 

## Hardware 
| Component | Spec |
| --- | --- | 
| Host | HP EliteDesk 800 G3 Mini |
| CPU | Intel i7-6700T |
| RAM | 24 GB DDR4-2400 SODIMM |
| Hypervisor | Proxmox VE 9.2.5 |
| Uplink | USB Wi-Fi adapter |

## Network Design 

The lab uses two bridges:

| Bridges | Purpose | Physical NIC | Subnet | 
| --- | --- | --- | --- |
| `vmbr0` | Proxmox management / internet | Yes | `10.0.0.0/24` |
| `vmbr1` | Isolated lab network | **None** | `10.10.10.0/24` |

`vmbr1` was created with no physical interface attached. Any VM placed on it can talk to other lab VMs and nothing else - no route to the home LAN, no route out. 

### Remote access without breaking isolation

The approach:

1. Tailscale installed on the **Proxmox host only** - not on any lab VM. 
2. `vmbr1` given the address `10.10.10.1`, creating a gateway presence on the isolated network
3. Proxmox configured to advertise `10.10.10.0/24` as a Tailscale subnet route
4. Lab VMs given `10.10.10.1` as their default gateway
 
The hypervisor is the only door in, and it is authenticated. 

**Concept note:** the lab VMs originally couldn't be reached even after the subnet route was approved, because they had no gateway configured. Advertising a route tells the outside world how to reach the network but setting a default gateway tells the machines inside how to actually answer. Both halves are required for traffic to actually complete a round trip.

## Virtual Machines 
| VM ID | Name | OS | Bridge | Address | Role |
| --- | --- | --- | --- | --- | --- | 
| 100 | `DC01` | Windows Server 2022 | `vmbr1` | `10.10.10.10` | Domain controller - `sentry.local` |
| 101 | `CLIENT01` | Windows 11 | `vmbr1` | `10.10.10.20` | Domain-joined workstation |
| 102 | `kali01` | Kali Linux 2026.2 | `vmbr0` + `vmbr1` | `10.0.0.131` / `10.10.10.30` | Attacker box | 

`kali01` is dual-homed on purpose: one interface on the lab network to run
enumeration against the domain, and one on the home LAN so tooling can be
installed and updated. The Windows VMs have no such second interface.

### Domain

`DC01` was promoted to domain controller for `sentry.local`, with `dcdiag`
passing cleanly before any misconfigurations were introduced - establishing a known-good baseline. `CLIENT01` was then joined to the domain.