
8a9
>
30a32
>                 self.port_table = PortTable()
150c152
<       self.allowOther(event)
---
>           self.allowOther(event)
178d179
<
181d181
<
183d182
<
185d183
<
190,192c188,222
<           log.debug("TCP it is !")
<    
<         self.replyToIP(packet, match, event, self.rules)
---
>             log.debug("TCP it is !")
>                       if False and not self.port_table.is_valid(src_mac=packet.src, src_ip=packet.payload.srcip):
>                           print "DDOS detected! install flow to block traffic from:%s to:%s", packet.src, packet.dst
>                           message = of.ofp_flow_mod() # OpenFlow massage. Instructs a switch to install a flow
>                           match = of.ofp_match() # Create a match
>                           match.dl_src = packet.src # Source address
>                           match.dl_dst = packet.dst # Destination address
>                           message.priority = 65535 # Set priority (between 0 and 65535)
>                           message.match = match          
>                           event.connection.send(message) # Send instruction to the switch
>                   self.replyToIP(packet, match, event, self.rules)
>
>
> class PortTable:
>
>     def __init__(self):
>         # this hash map will store source ip address for a given source mac
>         # hash map's key is mac and value is the ip address.
>         self.mac_to_ip_mapping = {}
>
>     def is_valid(self, src_mac, src_ip):
>         if src_mac not in self.mac_to_ip_mapping:  
>             print "this is a new mac, ip pair. Remember it in the hash map."
>             self.mac_to_ip_mapping[src_mac] = src_ip
>             return True
>         # source mac to source ip mapping already exists.
>         cached_src_ip = self.mac_to_ip_mapping[src_mac]
>         if cached_src_ip == src_ip:
>             print "got same IP for the mac address. looks good."
>             return True
>         else:
>             print("this is not valid ip address for the mac")
>             # block the flow if cached src ip does not match current src ip
>             return False
>
