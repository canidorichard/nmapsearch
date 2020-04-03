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
parms.add_argument("-d", "--debug", required=False, action="store_true", help="Debug output")
parms.add_argument("-o", "--output", type=str, required=False, default="xml_min", choices=['xml','xml_min','ipv4',"mac","mac+ipv4","ports","script"], help="Specify output format")
parms.add_argument("-p", "--path", type=str, required=False, default=".", help="Specify location of file(s)")
parms.add_argument("-r", "--regex", type=str, required=True, help="Search expression")
parms.add_argument("-s", "--port_state", required=False, default="open", choices=['all','closed','filtered','open'], help="Case sensitive search")

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

      # Get host details
      addr_ipv4=""
      addr_mac=""
      addresses=host.getElementsByTagName("address")
      for address in addresses:
        addr=address.getAttribute("addr")
        addrtype=address.getAttribute("addrtype")
        if addrtype == "ipv4": addr_ipv4 = addr
        if addrtype == "mac": addr_mac = addr

      hostname=""
      nametags=host.getElementsByTagName("hostname")
      for nametag in nametags:
        hostname=nametag.getAttribute("name")

      # Output minimal XML
      if args['output'] == "xml_min":
        hostxml=host.toxml()
        for m in regexp.finditer(hostxml):
          idxStart = m.start(0)
          idxStart = hostxml.rfind("<", 0, idxStart)
          idxEnd = m.end(0)
          idxEnd = hostxml.find(">", idxEnd) + 1
          print("")
          print("Host-FQDN: " + hostname)
          print("Host-Addr: " + addr_ipv4)
          print("")
          print(hostxml[idxStart:idxEnd])

      # Output XML
      elif args['output'] == "xml":
        print(host.toxml())

      # Output addresses
      if args['output'] == "ipv4" and addr_ipv4 != "": print(addr_ipv4)
      if args['output'] == "mac" and addr_mac != "": print(addr_mac)
      if args['output'] == "mac+ipv4" and addr_ipv4 != "": print(addr_mac + "|" + addr_ipv4)

      # Output ports
      if args['output'] == "ports":
        ports=host.getElementsByTagName("port")
        for port in ports:
          if regexp.search(port.toxml()):
            portid=port.getAttribute("portid")
            portstate=""
            states=port.getElementsByTagName("state")
            for state in states:
              portstate=state.getAttribute("state")
            name=""
            tunnel=""
            services=port.getElementsByTagName("service")
            for service in services:
              name=service.getAttribute("name")
              tunnel=service.getAttribute("tunnel")
            if name == "http" and tunnel == "ssl":
              name = "https"

            # Regex must be found in portid or service name
            if(regexp.search(portid) or regexp.search(name)):
              if (args['port_state'] == portstate or args['port_state'] == "all"):
                print(addr_ipv4+"|"+portid+"|"+name+"|"+tunnel+"|"+portstate)

      # Script output
      if args['output'] == "script":
        ports=host.getElementsByTagName("port")
        for port in ports:
          portid=port.getAttribute("portid")
          scripts=port.getElementsByTagName("script")
          for script in scripts:
            if regexp.search(script.toxml()):
              print("")
              print("Host-FQDN: " + hostname + ":" + portid)
              print("Host-Addr: " + addr_ipv4 + ":" + portid)
              print("")
              print(script.getAttribute("output"))


if __name__ == '__main__':
  # Execute main method
  main(args)
