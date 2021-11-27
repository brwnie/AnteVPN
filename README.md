# AnteVPN

This is the GitHub page of the plugin 'AnteVPN'. AnteVPN is currently in development and is not suitable for use on production servers.

## What/Who/Why

### What is AnteVPN?

AnteVPN is an amateur Paper plugin for Minecraft servers that checks the reputation of an IP addresses that connects to a Minecraft Server. If the IP address is found to be a VPN IP address it is blocked by the server.

AnteVPN is inspired by AntiVPN, however the code is original and not a fork

### Who is AnteVPN currently for?

AnteVPN is designed to be compatible for 1.17 and hopefully 1.18 servers.

### Who is AnteVPN currently _not_ for?

Commercial/for-profit Minecraft servers and communities, please pay someone to make a plugin for you.

Production servers, there is no active support or community currently offered for this plugin.

### Why AnteVPN?

AnteVPN was created as a small sticking plaster to Egg82's Anti-VPN plugin in advance of 1.18 releasing. 

Currently, Anti-VPN is not supported in 1.17 without the use of special start-up flags, and it is feared that it may break completely in 1.18

The quality of the code in AnteVPN is likely to be well below average, especially in comparison to the original Anti-VPN plugin. Well-seasoned programmers will likely cringe or find the source code hilarious (you're welcome).

AnteVPN was created as I struggled with the source code and set-up of Anti-VPN (it's my lack of skills, not the code) and wanted to ensure there was a supported Anti-VPN plugin for 1.18 for PaperMC

I also struggle with how version control systems work, so I figured I would give it a go.

## Installation

Grab the .jar from the [releases](https://github.com/brwnie/AnteVPN/releases) page and pop into the plugins folder

After first start-up, a SQLite database will be generated along with a configuration file

The configuration file is used to put the API keys from the various providers so the plugin can communicate with them.

Generally the plugin will block on the first bad result reported, and it requires two successful checks to allow an IP to be authenticated

## Commands

### avpnsim
Usage: /avpnsim <required: ip-address> [optional: provider]
Example: /avpn 1.2.3.4
Permission Required: cfuk.avpndebug

Simulates an IP request, requires debug mode to be on

### avpndebug
Usage: /avpndebug
Permission Required: cfuk.avpndebug
Turns on debug mode