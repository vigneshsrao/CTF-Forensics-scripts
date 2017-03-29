import dpkt
import sys

if len(sys.argv)<2:
        sys.exit("Usag: findfile.py <path/to/file>")

f = open(sys.argv[1])

c=0
pcap = dpkt.pcap.Reader(f)

for ts, buf in pcap:
    c+=1
    if "PNG" in buf:
        print "Found PNG in packet "+str(c)
        name = "PNG."+str(c)+".png"
        fo = open(name,'w')
        start = buf.index("PNG")-1
        end = len(buf)
        for i in range(start,end):
            fo.write(buf[i])
    if "JFIF" in buf:
        print "found JPEG in packet "+str(c)
    if "txt" in buf:
        print "Found text file in packet "+str(c)
    if ("GIF" in buf) or ("gif" in buf):
        print "Found GIF in packet "+str(c)
    if "504b0304" in buf.encode('hex'):
        print "Found zip file in packet "+str(c)
        name = "ZIP."+str(c)+".zip"
        fo = open(name,'w')
        start = buf.encode('hex').index("504b0304")/2
        end = len(buf)
        for i in range(start,end):
            fo.write(buf[i])
