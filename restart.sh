#!/bin/sh
sudo launchctl bootout system /Library/LaunchDaemons/net.saelo.capsd.plist
sudo launchctl bootout system /Library/LaunchDaemons/net.saelo.shelld.plist

sudo launchctl bootstrap system /Library/LaunchDaemons/net.saelo.capsd.plist
sudo launchctl bootstrap system /Library/LaunchDaemons/net.saelo.shelld.plist
