# pathfinder
A traceroute tool written in python that returns geographical information on each 'hop' along the way.
It does require root access, and this is considered dangerous in Python, so please review the code and
make sure you are okay with executing it on your machine. I am open to creative ways of accomplishing this
task without elevated privileges, so if you have any ideas, please submit them! Thanks!

To run:
```
$ sudo python3 pathfinder.py [hostname]
```
example:
```
$ sudo python3 pathfinder.py www.google.com
```
Requires:
```
scapy
urllib3
```
Uses from standard library:
```
ipaddress
json
```

Sample output:

![alt text](https://github.com/mcorybillington/pathfinder/blob/master/images/pathfinder.jpeg)