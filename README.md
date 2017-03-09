#What?
======
Let's say you run a capture of some wifi data and you want to know what networks other people are beaconing for - *creepy* will analyze the PCAP and print out a list of sending MAC addresses and the SSIDs they are searching for.

#Why?
====
I ran this program against a PyShark implementation that does the same thing.  The only reason I wrote this program was that the other one seemed prohibitively slow when analyzing large files.  I'm no genius, but I would go so far as to say these things:
 - Python is an interpreted language and in 99.9% of situations is at a speed disadvantage.
 - Go is compiled, thus inherently quicker (doubtless exceptions exist, this is not one).
 - Python was faster in terms of discovery, and writing the Golang code took longer, but the Go is for sure faster.
 - Go is not making calls to an external program; PyShark is making an async system call to tshark for every packet.  I'm sure there's a better way to do this.

That being said, if the PCAP format for 802.11 Probe Request tags ever changes, this code will break.  I am hopeful that this won't happen but without using libpcap there are no guarantees and I was not about to try that.  Splitting up the payload was a fun and enjoyable way to spend a few hours of vacation.

#Comparison
===========

Not a fair fight!  But if you want numbers:

Creepy
------

time ./creepy --filename=blah.pcap
real    0m2.268s
user    0m4.389s
sys     0m0.346s

Python Script
-------------

time python blah.py --filename=blah.pcap
real    13m28.068s
user    18m34.628s
sys     0m7.651s
