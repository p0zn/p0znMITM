# p0znMITM
## ARP Poisoning Tool

![](https://www.linkpicture.com/q/po0zn-mıtm.jpg)

## What is ARP?
Address Resolution Protocol (ARP) is a protocol or procedure that connects an ever-changing IP address to a fixed physical machine address, also known as a MAC address, in  LAN.

## What is ARP Poisoning?
ARP Poisoning is abuses weaknesses in the widely used Address Resolution Protocol (ARP) to disrupt, redirect, or spy on network traffic. 

## Features

- Automatic IP forwarding by operating system.
- Scanning with different interfaces (eth0,wlan0).
- Send and listen packets in one terminal.
- Returning to instant default settings with the reset feature. 
- Instant follow-up with quick response feature. 

## Requirement Installations

-p0znMITM developed with python3 
-Used with python 3 version

Use the "requirements.txt" file to install the requirements

```sh
sudo pip3 install requirements.txt
```

## Usage

You can use the help command to get information about the tool.

```sh
sudo python3 p0znMITM.py --help 
#or use -h command.
```

To use the p0znMITM tool, review the command line below

```sh
sudo python3 p0znMITM.py -t [target IP] -g [gateway IP] -i [network interface]
```

## License

MIT

Copyright 2021 p0zn

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.


