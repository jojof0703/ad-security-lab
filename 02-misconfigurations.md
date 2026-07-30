# 02 - Planted Misconfigurations 

Five misconfigurations were introduced deliberately, each chosen because it mirrors something that shows up in real environments - usually as the result of convenience, legacy decisions, or permissions granted once and never reviewed. 

This file is the ground truth. It was written before enumeration and kept off the lab machines so the discovery phase stayed blind

---

## 1. Kerberoastable service account - `svc-sql` 

**What was done:** a Service Principal Name was registered on `svc-sql`, a standard user account with a weak password. 

**Why it matters:** any authenticated domain user can request a Kerberos service ticket for an account with an SPN. That ticket is encrypted with the service account's password hash, so it can be taken offline and cracked at leisure - no further access to the domain required, and nothing that looks obviously like an attack at the time. 

**Real-world parallel:** service accounts get SPNs because an application needs one, then the account keeps a password set years ago that was never rotated because nobody's sure what systems would break 

## 2. AS-REP roastable user - `lgarcia`

**What was done:** on the HR user Lisa Garcia's account, `lgarcia`, the setting `Do not require Kerberos pre-authentication` was enabled. 

**Why it matters:** An attacker can simply request an AS-REP for this account with just a valid username, crack the returned hash offline, which is hashed with the same user's password key. This sets up kerberoasting perfectly. AS-REP is the foot in, Kerberoasting is the ladder up. 

**Real-world parallel:** older Kerberos implementation. Some Unix/Linux client or Java app couldn't figure out pre-auth correctly. Ticket gets opened, a switch is flipped to make auth work, closed ticket and a flag that lives on an individual account.

## 3. Excessive ACL - GenericAll over `svc-backup`

**What was done:** the IT user John Smith's account, `jsmith`, was given the GenericAll permission on the `svc-backup` account object.

**Why it matters:** if the `jsmith` account is ever compromised, the attacker can simply force a new password, even without prior knowledge of the old one, for the `svc-backup` account. They would own it outright but if the real user tried to log back in they would notice. Quieter techniques would be to create a misconfiguration and then erase it, since `jsmith` has full control. For example, a targeted kerberoasting by writing a SPN onto `svc-backup`, kerberoast it, crack the hash offline, set things back. Owner never notices because this time the password was never changed

**Real-world parallel:** Delegation group was granted 'full control' over an OU so they can reset passwords but it was scoped far too broadly or maybe an admin who couldn't get a specific right to work, granted GenericAll to make the error go away. 

## 4. Weakened Default Domain Policy 

**What was done:** The minimum password length setting was changed to 4, the complexity was disabled and the lockout threshold was set to 0. 

**Why it matters:** With these settings, an attacker can easily use brute force and even password spraying to crack the passwords. The attacker can hit all accounts under the domain as hard as they want because there's no lockout protection. This setting amplifies every other finding in this file. 

**Real-world parallel:** Loosened once for some system and it was never restored. 

## 5. Unconstrained delegation on `CLIENT01`

**What was done:** `userAccountControl` TRUSTED_FOR_DELEGATION flag was set via `Set-ADAccountControl` on `CLIENT01`, marking the machine trusted for unconstrained delegation. 

**Why it matters:** Any application, service, or process that is compromised can coerce a privileged user to authenticate to `CLIENT01`. Once they do, their TGT lands in memory which the attacker can scrape and grab to become them. The TGT is also the user's master ticket, so the attacker can reuse it to authenticate anywhere in that domain as that user. 

**Real-world parallel:** Older application server was set up this way and never migrated. 
