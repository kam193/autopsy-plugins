# Autopsy Python Plugins

This repository holds simple Python plugins for Autopsy. Tested on Autopsy 4.22.1

The supported cases are:

* Looking for hashes in CIRCL Hashlookup service (via DNS + REST for details)
* Looking for hashes in CymruMalwareHash (only DNS)

Currently, plugins use MD5 for checks AND require files to already have the hash
calculated. As so, you may need to at least once run the built-in "Hash lookup"
module with or before using those modules.

## Installation
Copy the directories to `python_modules` folder, e.g. in Linux it could be
`~/.autopsy/dev/python_modules`