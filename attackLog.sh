interface=eth0
dumpdir=/root

while /bin/true; do
  pkt_old=`grep $interface: /proc/net/dev | cut -d :  -f2 | awk '{ print $2 }'`
  sleep 1
  pkt_new=`grep $interface: /proc/net/dev | cut -d :  -f2 | awk '{ print $2 }'`

  pkt=$(( $pkt_new - $pkt_old ))
  echo -ne "\r$pkt packets/s\033[0K"

   if [ $pkt -gt 1000 ]; then
    echo -e "\n`date` Under Attack. Capturing Packets..."
	dateinfo=`date +"%d-%m-%y-%H:%M:%S"`
    tcpdump -n -s0 -c 1000 -w $dumpdir/TCPDUMP/pcap/capture.$dateinfo.pcap
	tshark -r /root/TCPDUMP/pcap/capture.$dateinfo.pcap -T fields -e ip.src > /root/TCPDUMP/report/report.$dateinfo.txt
	sort /root/TCPDUMP/report/report.$dateinfo.txt | uniq > /root/TCPDUMP/report/nodupes/report-nodup.$dateinfo.txt
    echo "$dateinfo Packets Captured. Analyzing..."
	tshark -r $dumpdir/TCPDUMP/pcap/capture.$dateinfo.pcap -T fields -E header=y -e ip.proto -e tcp.flags -e udp.srcport -e tcp.srcport -e data > /root/TCPDUMP/ramdom/$dateinfo.txt
	python3 attackNotify.py /root/TCPDUMP/ramdom/$dateinfo.txt capture.$dateinfo.pcap
    sleep 120  && pkill -HUP -f /usr/sbin/tcpdump
  fi
done
