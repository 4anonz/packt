# packt
packt is a simple CL(command line) network packet sniffer which can run
on any unix-like OS including termux (Android).
packt works by first opening a RAW socket and receives every outgoing and incoming packets.
Before runing packt you have to be root.
packt cannot run on windows.

# Screenshots
![Test Image1](https://raw.githubusercontent.com/4anonz/packt/master/demo/packt.png)
![Test Image1](https://raw.githubusercontent.com/4anonz/packt/master/demo/packt4.png)
![Test Image1](https://raw.githubusercontent.com/4anonz/packt/master/demo/packt5.png)

# features
* Completly Written in C.
* packt can capture all incoming and outgoing packets.
* packt can capture packets on a specific network interface.
* packt can also sniff on a specific protocol(TPC, UDP or ICMP)
* packt can capture all packet headers, like ethernet header, ip headers and protocol header
* packt can capture all the data payload
* packt supports TCP, UDP, ICMP protocols.

Because some other protocols like HTTP, HTTPS, SSH, FTP etc, are build on the TCP protcol.
packt can also capture those protocols and any other protocol that was build on the TCP or UDP protocol.

# Installation
```
git clone https://github.com/4anonz/packt.git
cd packt
sudo make
sudo packt --help
```
# Commands
```
Usage: packt [OPTIONS] <args>
Version 0.0.1
     -h, --help                  Print this help message and exit.
     -i --interface              Specify the interface to sniff packets on.
     -w --write                  Specify a file name to save all captured packets.
    By default packt will sniff all types of packets, but the following options are also available.
    SNIFFING OPTIONS:
      --tcp                       Sniff TCP packets only.
      --udp                       Sniff UDP packets only.
      --icmp                      Sniff ICMP packets only.
      --all                       Sniff all packets, this is the default options.
```
As you can see the commands are quite easy.
if there isn't anything you want to special you can just use "sudo packt"
to start capturing all packets on any interface.

Please don't forget to report bugs or send feed backs.
# Author
* [Contact](https://facebook.com/4anonz) - Anonymous Hacks(4anonz)

Please don't forget to leave a star 😉️
