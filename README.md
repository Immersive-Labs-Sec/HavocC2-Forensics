# HavocC2-Forensics
A set of tools and resources for analysis of Havoc C2


## Detection Rules

### Yara

- havoc-c2-memory.yar - Detects Havoc C2 in memory

## Volatility

A Volatilty 3 plugin has been created to detect the presence of Havoc C2 in memory. The plugin is located in the `Volatility` directory. An example of running the plugin is shown below:

```
vol -r pretty -p ./Volatility/ -f Win10-Analysis-Snapshot13.vmem havoc.Havoc --pid 5544
Volatility 3 Framework 2.5.2
Formatting...0.00               PDB scanning finished                        
  |  PID |        Process | Agent ID |                                                          AES Key |                           AES IV
* | 5544 | chrome-updater | 4b9ccaea | 8c0a8026307278b0de8472a2407c08a83cd22004b2e8d672f0549232d6081efc | 900ec8ccc246b25e242276781420f40e
```

The detection works by identifying the magic bytes `de ad be ef` in the process memory. If your sample uses different magic you can use the `--magic` flag to specify the magic bytes.



## Packet Capture

The packet capture directory contains a script to parse Havoc C2 traffic from a packet capture. The script has a few requirements. 

Python Libraries
- Python3
- PyCryrptoDome
- PyShark

OS Tools

- tshark

Caveats

The script will only detect HTTP traffic or HTTPS traffic that has been decrypted for example with TLS MASTER Keys.

The script can be run with the command show below. The script will attempt to detect the init request that contains the AES Key and IV, if not in the pcap then you can use the `--key` and `--iv` flags to specify the key and IV.


```
python3 havoc-pcap-parser.py --pcap Havoc-MemoryCapture.pcapng
[+] Filtering for HTTP traffic
[+] Agent -> Team Server
[+] Found Havoc C2
  [-] Agent ID: 2f09db1e
  [-] Magic Bytes: deadbeef
  [-] C2 Address: http://havoc-http.the-briar-patch.cc/Collector/2.0/settings/
[+] Found AES Key
  [-] Key: d0f40032e0347cf4f42472ae2066e6eac82ce0d28ce8e4829edcc41ec48836d6
  [-] IV: dc0a16f0046c3c24bed2e29e88805296
```