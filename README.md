getiocmisp
==========

getiocmisp is a [Splunk](https://www.splunk.com) custom search command that helps to extract IOCs from a [MISP](http://misp-project.org/) instance.

![alt text](https://blog.rootshell.be/wp-content/uploads/2017/10/splunk-misp-1-1024x729.png)

getiocmisp relies on PyMISP. PyMISP requires Python 3 but only Python 2.7 is available in the Splunk environment. 
The script getiocmips.py is a wrapper and calls get-ioc-misp.py. This is best to keep your Splunk instance clean.

Prerequisites
=============
1. Install Python 3 on the Splunk server
2. Install Splunk-SDK for Python (see http://dev.splunk.com/view/python-sdk/SP-CAAAEDG)
3. Install PyMISP (see https://github.com/CIRCL/PyMISP)

Installation
============

1. Copy app_getmispioc to $SPLUNK_HOME/etc/apps/

2. Copy scripts/* to /usr/local/bin

3. Edit /usr/local/bin/mispconfig.py and specify your MISP URL and authorization key

4. Restart Splunk

Usage
=====
See https://blog.rootshell.be/2017/10/31/splunk-custom-search-command-searching-misp-iocs/
