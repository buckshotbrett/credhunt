# credhunt

## Description
This tool is a CrackMapExec plugin that is used to spider shares while hunting for credentials and other interesting files. It combines code, features, and rules from the excellent CrackMapExec [spider_plus.py](https://github.com/byt3bl33d3r/CrackMapExec/blob/master/cme/modules/spider_plus.py) plugin and the amazing [Snaffler](https://github.com/SnaffCon/Snaffler). By implementing the triage rules from Snaffler, the same triage prioritization is used: Black is the most interesting, then Red, Yellow, and finally Green. This tool allows you to test from Linux while enjoying automated credential hunting capabilities similar to Snaffler.

## Installation
It was implemented as a single file plugin to make installation easier. It simply needs to be copied CrackMapExec's modules folder.

## Usage
It requires no arguments and is executed as follows against a target or list of targets:

`crackmapexec smb [TARGET] -u '[USER]' -p '[PASSWORD]' -d '[DOMAIN]' -M credhunt`

## Notes
* There is currently no logging option, so piping the above command to `tee` will save all your output.
* This tool is only to be used for authorized security auditing.

Happy Hunting!
