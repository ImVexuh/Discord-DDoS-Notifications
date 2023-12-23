import requests, json, sys
URL = 'webhook here'
true = 'true'
false = 'false'

file = open(sys.argv[1], "r")
dateinfo = sys.argv[2]
capture_file = file.read()

definitionVer = "1.0.5"
attack_types = {
  "[UDP]": "17      ",
  "[ICMP]": "1      ",
  "[ICMP Dest Unreachable]": "1,17      ",
  "[IPv4/Fragmented]": "4       ",
  "[GRE]": "47      ",
  "[IPX]": "111     ",
  "[AH]": "51       ",
  "[ESP]": "50      ",
  "[OpenVPN Reflection]": "17       1194",
  "[VSE Flood/1]": "17      27015",
  "[RRSIG DNS Query Reflection]": "002e0001",
  "[ANY DNS Query Reflection]": "00ff0001",
  "[NTP Reflection]": "17       123",
  "[Chargen Reflection]": "17       19",
  "[MDNS Reflection]": "17      5353",
  "[BitTorrent Reflection]": "17        6881",
  "[SADP Reflection]": "17        37020",
  "[CLDAP Reflection]": "17     389",
  "[STUN Reflection]": "17      3478",
  "[STUN Reflection/2]": "17      8088",
  "[STUN Reflection/3]": "17      37833",
  "[MSSQL Reflection]": "17     1434",
  "[SNMP Reflection]": "17      161",
  "[WSD Reflection]": "17       3702",
  "[DTLS Reflection]": "17      443     40",
  "[OpenAFS Reflection]": "17       7001",
  "[ARD Reflection]": "17       3283",
  "[BFD Reflection]": "17       3784",
  "[SSDP Reflection]": "17      1900",
  "[ArmA Reflection/1]": "17        2302",
  "[ArmA Reflection/2]": "17        2303",
  "[vxWorks Reflection]": "17       17185",
  "[Plex Reflection]": "17      32414",
  "[TeamSpeak Reflection]": "17     9987",
  "[Lantronix Reflection]": "17     30718",
  "[DVR IP Reflection]": "17        37810",
  "[Jenkins Reflection]": "17       33848",
  "[Citrix Reflection]": "17        1604",
  "[NAT-PMP Reflection]": "008000",
  "[Memcache Reflection]": "17      11211",
  "[NetBIOS Reflection]": "17       137",
  "[SIP Reflection]": "17       5060",
  "[Digiman Reflection]": "17       2362",
  "[Crestron Reflection]": "17      41794",
  "[CoAP Reflection]": "17      5683",
  "[BACnet Reflection]": "17        47808",
  "[FiveM Reflection]": "17     30120",
  "[Modbus Reflection]": "17        502",
  "[QOTD Reflection]": "17      17",
  "[ISAKMP Reflection]": "17        500",
  "[XDMCP Reflection]": "17     177",
  "[IPMI Reflection]": "17      623",
  "[SLP Reflection]": "17      427",
  "[Sentinel Reflection]": "17      5093",
  "[Apple serialnumberd Reflection]": "17       626",
  "[TP240 Reflection]": "17       10074",
  "[UDPMIX DNS Flood]": "7065616365636f7270",
  "[TSource Engine Query]": "54536f75726365",
  "[Known Botnet UDP Flood/1]": "52794d47616e67",
  "[Known Botnet UDP Flood/2]": "a6c300",
  "[Known Botnet UDP Flood/3]": "e1d8dbbcce7bf1",
  "[OVH-RAPE/1]": "fefefefe",
  "[OVH-RAPE/2]": "4a4a4a4a",
  "[TeamSpeak Status Flood]": "545333494e49",
  "[Flood of 0xFF]": "fffffffffff",
  "[UDP getstatus Flood]": "676574737461747573",
  "[KILLALL Reflection/1]": "0x00000012     443",
  "[TCP Reflection from HTTPS/2]": "0x00000010      443",
  "[SPEEDTEST]": "0x00000010        8080",
  "[TCP Reflection from HTTP/2]": "0x00000010       80",
  "[TCP Reflection from BGP/1]": "0x00000012        179",
  "[TCP Reflection from BGP/2]": "0x00000010        179",
  "[TCP Reflection from SMTP/1]": "0x00000012       465",
  "[TCP Reflection from SMTP/2]": "0x00000010       465",
  "[TCP SYN-ACK]": "0x00000012",
  "[TCP PSH-ACK]": "0x00000018",
  "[TCP RST-ACK]": "0x00000014",
  "[TCP FIN]": "0x00000001",
  "[TCP SYN]": "0x00000002",
  "[TCP PSH]": "0x00000008",
  "[TCP URG]": "0x00000020",
  "[TCP RST]": "0x00000004",
  "[TCP ACK]": "0x00000010",
  "[Unset TCP Flags]": "0x00000000",
  "[TCP SYN-ECN-CWR]": "0x000000c2",
  "[TCP SYN-ECN]": "0x00000042",
  "[TCP SYN-CWR]": "0x00000082",
  "[TCP SYN-PSH-ACK-URG]": "0x0000003a",
  "[TCP SYN-ACK-ECN-CWR]": "0x000000d2",
  "[TCP PSH-ACK-URG]": "0x00000038",
  "[TCP FIN-SYN-RST-PSH-ACK-URG]": "0x0000003f",
  "[TCP RST-ACK-URG-CWR-Reserved]": "0x000004b4",
  "[TCP SYN-PSH-URG-ECN-CWR-Reserved]": "0x000004ea",
  "[TCP FIN-RST-PSH-ECN-CWR-Reserved]": "0x00000ccd",
  "[TCP FIN-RST-PSH-ACK-URG-ECN-CWR-Reserved]": "0x00000cfd"
}

attack_type = ''

for occurrences in attack_types:
  # print(attack_types[occurrences])
  number = capture_file.count(attack_types[occurrences])
  if number > 2000:
    attack_type = attack_type + " " + occurrences

if attack_type == '':
  attack_type = "Undetermined"

payload = {
  "embeds": [
    {
      "title": "NaniteVPN",
      "description": "Attack Detected",
      "url": "https://www.nanitehosting.com/",
      "color": 16056320,
      "fields": [
        {
          "name": "Server:",
          "value": "Amsterdamn, Netherlands",
          "inline": true
        },
        {
          "name": "IP Address:",
          "value": "185.35.x.x",
          "inline": true
        },
        {
          "name": "Host:",
          "value": "RoyaleHosting BV",
          "inline": true
        },
        {
          "name": "PCAP Name:",
          "value": dateinfo,
          "inline": true
        },
        {
          "name": "Attack Type",
          "value": attack_type
        }
      ],
      "author": {
        "name": "nDefend Mitigation",
        "url": "https://www.nanitehosting.com/",
        "icon_url": "https://cdn.discordapp.com/attachments/1096329050471022694/1187317240123637810/NaniteBlackBG.jpg?ex=65967259&is=6583fd59&hm=29957d86456abb7f1bf7809431df33b41162e0ba11ecc7feefaed2b6a1906f0a&"
      },
      "footer": {
        "text": "Attack Has Been Captured",
        "icon_url": "https://cdn.discordapp.com/attachments/1096329050471022694/1187317240123637810/NaniteBlackBG.jpg?ex=65967259&is=6583fd59&hm=29957d86456abb7f1bf7809431df33b41162e0ba11ecc7feefaed2b6a1906f0a&"
      },
      "thumbnail": {
        "url": "https://cdn.discordapp.com/attachments/1096329050471022694/1187317240123637810/NaniteBlackBG.jpg?ex=65967259&is=6583fd59&hm=29957d86456abb7f1bf7809431df33b41162e0ba11ecc7feefaed2b6a1906f0a&"
      }
    }
  ]
}
header_data = {'content-type': 'application/json'}
requests.post(URL, json.dumps(payload), headers=header_data)
