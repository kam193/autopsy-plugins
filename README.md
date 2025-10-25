# Autopsy Python Plugins

This repository holds simple Python plugins for Autopsy. Tested on Autopsy 4.22.1

The supported cases are:

* Looking for hashes in CIRCL Hashlookup service (via DNS + REST for details)
* Looking for hashes in CymruMalwareHash (only DNS)

Currently, plugins use MD5 for checks and will calculate it if it doesn't
exist.

The CIRCL Hashlookup will analyze the trust level delivered from the service, and
take actions based on it:

* < 30: add to untrusted set (notable)
* 30-49: add to likely untrusted set (likely notable)
* 50-79: add to likely trusted set AND mark file as known (likely not notable)
* >= 80: add to trusted set AND mark file as known (not notable)

The Cymru Malware Hash plugin will mark hits as malware.

## Installation
Copy the directories to `python_modules` folder, e.g. in Linux it could be
`~/.autopsy/dev/python_modules`