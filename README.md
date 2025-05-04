# PCAP to Time Series Extractor

<details>

<summary>Install required tools on Linux</summary>

### For Ubuntu 18.04, 20.04, 22.04

```bash
sudo apt-get update
```
</details>


<details>

<summary>Install required python libs</summary>

### pip install
```bash
pip install -r requirements.txt
python3 setup.py install
```

### conda install
```bash
conda config --add channels conda-forge
conda install --file requirements_conda.txt
python3 setup.py install
```

</details>


## TCP/IP Model
<p align="left" href="https://cyberthreatdefence.com/"> 
<a href="https://cyberthreatdefence.com/"><picture><img width="15%" height="auto" src="./assets/tcp-ip-model.png" height="175px" alt="TCP-IP-MOdel"/></picture></a>
</p>

| Layer             | Function                                                                                                                               | Protocols                                     |
|-------------------|----------------------------------------------------------------------------------------------------------------------------------------|-----------------------------------------------|
| Application Layer | Provides network services directly to end-user applications. It handles application-level protocols and interfaces with user software. | HTTP, FTP, SMTP, DNS, RIP, SNMP               |
| Transport Layer   | Manages end-to-end communication and data transfer reliability. It is responsible for error recovery, flow control, and ensuring data integrity. | TCP, UDP                                      |
| Internet Layer    | Handles logical addressing and routing of data packets across the network. It determines the best path for data from the source to the destination. | IP, ARP, ICMP, IGMP                             |
| Network Access Layer | Manages physical network hardware and data framing. It handles the communication between devices on the same network segment and provides error detection. | Ethernet, PPP                                 |