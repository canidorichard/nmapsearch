#!/usr/bin/env python3

# Copyright (c) 2019, Richard Hughes All rights reserved.
# Released under the BSD license. Please see LICENSE.md for more information.

import sys
import os
import argparse
import glob
import xml.dom.minidom
import re

# Define command line arguments
parms=argparse.ArgumentParser()
parms.add_argument("-f", "--file", type=str, required=False, default="*.xml", help="Specify input file(s)")
parms.add_argument("-c", "--case_sensitive", required=False, action="store_true", help="Case sensitive search")
parms.add_argument("-o", "--output", type=str, required=False, default="xml_min", choices=['xml','xml_min','ipv4',"mac","mac+ipv4","ports"], help="Specify output format")
parms.add_argument("-p", "--path", type=str, required=False, default=".", help="Specify location of file(s)")
parms.add_argument("-r", "--regex", type=str, required=True, help="Search expression")
parms.add_argument("-d", "--debug", required=False, action="store_true", help="Debug output")
args = vars(parms.parse_args())

# Globals
errorsexist = False

# Main processing
def main(args):
  # If output format is XML then add root element
  if args['output'] == "xml":
    print("<hosts>")

  # Generate list of files and pass for processing
  for file in glob.glob(args['path'] + "/" + args['file']):
    # Process file if it is not empty
    if os.path.getsize(file) > 0:
      procFile(file)

  # If output format is XML then close root element
  if args['output'] == "xml":
    print("</hosts>")

  if(not args['debug'] and errorsexist): print("\nWARNING: Run with -d to see files that could not be processed", file=sys.stderr) 


# Process file
def procFile(file):

  global errorsexist

  # Parse XML file
  try:
    doc=xml.dom.minidom.parse(file)
    # Verify this is an Nmap output file
    if doc.getElementsByTagName("host") or doc.getElementsByTagName("nmaprun"):
      # Compile regular expression
      if not args['case_sensitive']:
        regexp = re.compile(args['regex'], re.IGNORECASE)
      else: 
        regexp = re.compile(args['regex'])
      procDocument(doc,regexp) 
    else:
      if args['debug']: print("WARNING: " + file + " is not a valid Nmap output file", file=sys.stderr)
      errorsexist=True
  except:
    if args['debug']: print("WARNING: Unable to parse " + file, file=sys.stderr)
    errorsexist=True


# Process document
def procDocument(doc,regexp):

  # Extract hosts
  hosts=doc.getElementsByTagName("host")
  for host in hosts:
    
    # Check for regular expression match
    if regexp.search(host.toxml()):

      # Get network addresses for host
      addresses=host.getElementsByTagName("address")
      addr_ipv4=""
      addr_mac=""
      for address in addresses:
        if args['output'] == "xml_min": print(address.toxml())
        addr=address.getAttribute("addr")
        addrtype=address.getAttribute("addrtype")
        if addrtype == "ipv4": addr_ipv4 = addr
        if addrtype == "mac": addr_mac = addr

      # Get hostnames
      hostnames=host.getElementsByTagName("hostname")
      for hostname in hostnames:
        if args['output'] == "xml_min": print(hostname.toxml())

      # Output minimal XML
      if args['output'] == "xml_min":
        hostxml=host.toxml()
        for m in regexp.finditer(hostxml):
          idxStart = m.start(0)
          idxStart = hostxml.rfind("<", 0, idxStart)
          idxEnd = m.end(0)
          idxEnd = hostxml.find(">", idxEnd) + 1
          print(hostxml[idxStart:idxEnd])

      # Output XML
      elif args['output'] == "xml":
        print(host.toxml())

      # Output addresses
      if args['output'] == "ipv4" and addr_ipv4 != "": print(addr_ipv4)
      if args['output'] == "mac" and addr_mac != "": print(addr_mac)
      if args['output'] == "mac+ipv4" and addr_ipv4 != "": print(addr_mac + "|" + addr_ipv4) 

      # Output potential web pages
      if args['output'] == "ports":
        ports=host.getElementsByTagName("port")
        for port in ports:
          if regexp.search(port.toxml()):
            portid=port.getAttribute("portid")
            services=port.getElementsByTagName("service")
            for service in services:
              name=service.getAttribute("name")
              tunnel=service.getAttribute("tunnel")
            # Regex must be found in portid or service name
            if(regexp.search(portid) or regexp.search(name)):
              # If we are looking for http
              if args["regex"] == "http":
                if tunnel == "ssl":
                  name="https"
                else:
                  name="http"
              print(addr_ipv4+"|"+portid+"|"+name+"|"+tunnel)



if __name__ == '__main__':
  # Execute main method 
  main(args)

