
# A network traffic monitoring tool using the Packet Capture library
### General Info
------------
The main part of the Assignment_6 is to create a tool that:
- Captures in real time packets drom an intenet device.
- Capture packets from an input file.
- Print some statistics about the captured packets.

I. FILE LIST
------------
- README                         This file.
- monitor.c                      The actual tool that captures packets.
- MakeFile                       MakeFile,everyone knows it :).
- listLib.c                      A library that helps the main tool keep track of its statistics.
- listLib.h
  
II. INSTALLATION
------------
1. Just run make command.


III. COMMAND LINE ARGUMENTS EXAMPLES
------------

 ```sh sudo monitor -i <Device> ```<br />
 ```sh sudo monitor -r <file_name> ```<br />

IV. EXTRA INFOS
------------

When we have a TCP packet,we can tell if it is retransmitted base on its sequency number.
If the seq_number of a captured TCP packet is smaller than the seq_number of the previous non-retransmitted
packet,then the packet is retransmitted.
    However we can't tell if a UDP packet is retransmitted,because the delivery of data to the destination cannot be guaranteed in UDP.
So UDP packets haven't a seq_number,because they dont need one.
    In this project restransmitted packets are marked only in -i mode,because in -r mode we can't tell who is the receiver and how is the sender,because 
we dont know the mac Adress of the pc that has captured the packets.We dont have a reference point.