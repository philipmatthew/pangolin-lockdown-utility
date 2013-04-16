#!/bin/sh
#####################################################################################
# pangolin_lockdown.sh - Script to perform basic hardening for Ubuntu 12.04 LTS 
#               (precise pangolin) systems via iptables and remove applications 
#               dangerous to user privacy.  Performs the following functions: 
#
#               1. Disallows all inbound network traffic except for SSH.  
#
#               2. Turns off IP forwarding.  
#
#               3. Disallows outbound traffic to specific servers related to 
#                  Canonical's geo IP service due to privacy concerns with 
#                  persistent connections. 
#
#               4. Removes applications deemed dangerous to privacy, including:
#                  - zeitgeist which tracks user activity such as files opened, 
#                    URLs visited conversations, etc. 
#                  - whoopsie which submits OS and application crash dumps to 
#                    Ubuntu which could contain sensitive information from 
#                    system memory.
#
#               5. Provides list of commands to run in order to remove all 
#                  directories containing zeitgeist tracking information.
#
# Author  - Lamar Spells (lamar.spells@gmail.com)
# Blog    - http://foxtrot7security.blogspot.com
# Twitter - lspells
#
# Copyright (c) 2013, Lamar Spells
# All rights reserved. Distributed under New BSD License.
#
# Redistribution and use in source and binary forms, with or without modification,
# are permitted provided that the following conditions are met:
#
# - Redistributions of source code must retain the above copyright notice, this
# list of conditions and the following disclaimer.
# - Redistributions in binary form must reproduce the above copyright notice,
# this list of conditions and the following disclaimer in the documentation
# and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
# IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
# INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
# BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
# DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
# LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE
# OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
# OF THE POSSIBILITY OF SUCH DAMAGE.
#
#####################################################################################

if [ `whoami` != "root" ] ; then
   echo "This script must be run as root"
   exit 1
fi

check_err()
{
   if [ $1 -ne 0 ] ; then
      echo "Error in script execution - Return code $1"
      exit $1
   else
      echo "  Completed"
   fi
}

echo "====================================="
echo " Lockdown Script for Ubuntu 12.04LTS "
echo "====================================="

echo "- Install or upgrade iptables package"
apt-get install iptables
check_err $?

echo "- Install or upgrade iptables persistent so that rules persist after reboot"
echo "  (ANSWER YES TO ALL QUESTIONS WHEN PROMPTED)"
apt-get install iptables-persistent
check_err $?

echo "- Stop iptables persistence service" 
service iptables-persistent flush 
check_err $?

echo "- Rolling back to default iptables rules..."
iptables -F
check_err $?

echo "- Persist default iptables rules"
service iptables-persistent save
check_err $?

echo "- Allow all current connections so that we don't disconnect our SSH session"
iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
check_err $?

# NOTE: Clone this section to create rules for HTTP, HTTPS, etc. 
echo "- Allowing future SSH connections"
iptables -A INPUT -p tcp --dport ssh -j ACCEPT
check_err $?

echo "- Dropping all other inbound traffic other than SSH"
iptables -A INPUT -j DROP
check_err $?

echo "- Allowing loopback traffic from localhost"
iptables -I INPUT 1 -i lo -j ACCEPT
check_err $?

echo "- Blocking outbound traffice to Canonical geo ip servers due to privacy concerns"
iptables -A OUTPUT -d 91.189.94.25 -j DROP
check_err $?
iptables -A OUTPUT -d 91.189.89.144 -j DROP
check_err $?

echo "- Disable IP Forwarding"
iptables -A FORWARD -j DROP
check_err $?

echo "- Persist new iptables rules in /etc/iptables"
service iptables-persistent save
check_err $?

echo "- Start persistence service"
service iptables-persistent start
check_err $?

echo "- iptables rules now in effect are as follows:"
echo "==============================================================================\n"
iptables -L -v
echo "\n==============================================================================\n"

echo "- Removing application dangerous to privacy [whoopsie]"
apt-get remove whoopsie
check_err $?

echo "- Removing application dangerous to privacy [zeitgeist]"
apt-get remove zeitgeist zeitgeist-core zeitgeist-datahub python-zeitgeist
check_err $?

echo "\n- Run the following commands to remove directories "
echo "  that contain zeitgeist tracking information:\n"
echo "  ================================================="
cat /etc/passwd | awk -F':' '{print $6}' | while read home_dir
do
   zeitgeist_dir="$home_dir/.local/share/zeitgeist"
   if [ -d $zeitgeist_dir ] ; then
      echo "  rm -rf $zeitgeist_dir"
   fi
done
echo "  ================================================="

echo "\n- Lockdown complete\n"
exit 0

