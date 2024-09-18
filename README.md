_DISCLAIMER: These tools and scripts are intended for educational purposes only. Do not attempt to use these against networks that you are unauthorized to test._

**AD Enumeration**

These scripts assist with enumeration and misconfiguration identification performed during an internal penetration test (assumed breach scenario) from an unauthenticated or authenticated perspective. 
This is by no means an exhaustive list of enumeration steps to perform, but automates a lot of steps I perform on each engagement and the intention of these scripts was to make the testing process more efficient & work on my scripting abilities. 
There may be tweaks and improvements that can be made!

**Scripts Overview**

**ad_unauth.py** - This script allows you to perform unauthenticated enumeration in an AD environment to assist in establishing an authenticated or privileged internal foothold.

**Usage: python3 ad_unauth.py**

**ad_auth.py** - This script allows you to perform authenticated enumeration in an AD environment to assist in identifying attack vectors for lateral movement and/or privilege escalation.

_Required tools:
certipy (if using certipy-ad - change the code) | nxc | impacket_

**Usage: python3 ad_auth.py**
