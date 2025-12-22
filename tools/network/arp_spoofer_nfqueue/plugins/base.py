from abc import ABC, abstractmethod
from argparse import ArgumentParser
from scapy.all import IP

class PacketPlugin(ABC):
    """
    Base class for NFQUEUE packet processing plugins.
    """
    
    @property
    def name(self) -> str:
        return self.__class__.__name__

    @abstractmethod
    def register_args(self, parser: ArgumentParser):
        """Register CLI arguments for this plugin."""
        pass

    @abstractmethod
    def configure(self, args):
        """Configure the plugin based on parsed arguments."""
        pass

    @abstractmethod
    def process_packet(self, ip_pkt: IP, ctx: dict) -> bool:
        """
        Process an intercepted packet.
        
        Args:
            ip_pkt (IP): The Scapy IP packet.
            ctx (dict): Context dictionary containing keys like 'iface', 'attacker_mac', 'victim_mac'.

        Returns:
            bool: True if the packet was 'handled' (consumed/hijacked) and should be DROPPED
                  by the NFQUEUE mechanism. False if the packet should continue to be processed
                  (and eventually ACCEPTED if no other plugin handles it).
        """
        pass
