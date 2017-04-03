from __future__ import print_function
from subprocess import Popen, PIPE
from string import printable
import dpkt
import sys

def PNG(b,n):
    print ("Found PNG in packet "+str(n))
    name = "PNG."+str(n)+".png"
    fo = open(name,'w')
    start = b.index("PNG")-1
    end = len(b)
    for i in range(start,end):
        fo.write(b[i])
    fo.close()

def JPEG(b,n):
    print ("found JPEG in packet "+str(n))
    start = b.encode('hex').index("ffd8ff")/2
    end = len(b)
    name = "JPEG."+str(n)+".jpg"
    fo = open(name,'w')
    for i in range(start,end):
        fo.write(b[i])
    fo.close()

def TXT(b,n):
    print ("Found text file in packet "+str(c)+"\t",end='')
    start = buf.index("txt")-10
    end = buf.index("txt")+10
    for i in range(start,end):
        if buf[i] in printable:
            print (buf[i],end='')
        else:
            print (".",end='')
    print ()

def ZIP(b,n):
    print ("Found zip file in packet "+str(n))
    name = "ZIP."+str(n)+".zip"
    fo = open(name,'w')
    start = b.encode('hex').index("504b0304")/2
    end = len(b)
    for i in range(start,end):
        fo.write(b[i])
    fo.close()

def arc7Z(b,n):
    print ("Found 7z archive in packet "+str(n))
    name = "7Z."+str(n)+".7z"
    fo = open(name,'w')
    start = b.encode('hex').index('377abcaf271c')/2
    end = len(b)
    for i in range(start,end):
        fo.write(b[i])
    fo.close()




if len(sys.argv)<2:
        sys.exit("Usage: python findfile.py <path/to/pcap_file>")
try:
    f = open(sys.argv[1])
except IOError:
    sys.exit("File not found!")

c=0
try:
    pcap = dpkt.pcap.Reader(f)
except Exception:
    exc = Popen(["file",sys.argv[1]], stdout=PIPE)
    print ("Not a pcap file\nUsage: python findfile.py <path/to/pcap_file>")
    sys.exit(exc.communicate()[0])
for ts, buf in pcap:
    c+=1
    if "PNG" in buf:
        PNG(buf,c)
    if "ffd8ff" in buf.encode('hex'):
        JPEG(buf,c)
    if "IEND" in buf:
        print ("PNG end in packet "+str(c))
    if ".txt" in buf:
        TXT(buf,c)
    if ("GIF" in buf):
        print ("Found GIF in packet "+str(c))
    if "504b0304" in buf.encode('hex'):
        ZIP(buf,c)
    if "504b0506" in buf.encode('hex'):
        print ("Empty zip archive found in packet "+str(c))
    if "504b0708" in buf.encode('hex)'):
        print ("Spanned zip archive found in packet "+str(c))
    if "377abcaf271c" in buf.encode('hex'):
        arc7Z(buf,c)
