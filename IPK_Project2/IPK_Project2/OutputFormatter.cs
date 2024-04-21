using System.Text;
using PacketDotNet;
using SharpPcap;

namespace IPK_Project2;

public class OutputFormatter
{
    public static string FormatOutput(PacketCapture rawCapture)
    {
        //Getting packet from rawCapture
        Packet packet = Packet.ParsePacket(rawCapture.GetPacket().LinkLayerType, rawCapture.GetPacket().Data);
        
        //Formatting output
        return "timestamp: " + ConvertToRfc3339(rawCapture.GetPacket().Timeval) +
               "\nsrc MAC: " + FormatMac(packet, true) +
               "\ndst MAC: " + FormatMac(packet, false) +
               "\nframe length: " + rawCapture.GetPacket().Data.Length +
               "\nsrc IP: " + ParseIpAddress(packet, true) +
               "\ndst IP: " + ParseIpAddress(packet, false) +
               "\nsrc port: " + ParsePort(packet, true) +
               "\ndst port: " + ParsePort(packet, false) +
               "\n" + FormatHexDump(rawCapture.GetPacket().Data);
    }
    
    private static string ParseIpAddress(Packet packet, bool src)
    {
        //Check if packet is ARP, because ARP doesn't have IP layer
        ArpPacket? arp = packet.Extract<ArpPacket>();
        if (arp == null)
        {
            //Check if this should return source or destination IP
            return src ? packet.Extract<IPPacket>().SourceAddress.ToString() : packet.Extract<IPPacket>().DestinationAddress.ToString();
        }
        else
        {
            //Check if this should return source or destination IP
            return src ? arp.SenderProtocolAddress.ToString() : arp.TargetProtocolAddress.ToString();
        }
    }
    
    private static string ParsePort(Packet packet, bool src)
    {
        //Check if packet is TCP or UDP and return source or destination port
        if (packet.Extract<TcpPacket>() != null)
        {
            //Check if this should return source or destination IP
            return src ? packet.Extract<TcpPacket>().SourcePort.ToString() : packet.Extract<TcpPacket>().DestinationPort.ToString();
        }
        if (packet.Extract<UdpPacket>() != null)
        {
            //Check if this should return source or destination IP
            return src ? packet.Extract<UdpPacket>().SourcePort.ToString() : packet.Extract<UdpPacket>().DestinationPort.ToString();
        }
        
        return "NaN";
    }
    
    private static string ConvertToRfc3339(PosixTimeval timeval)
    {
        // Convert PosixTimeval to DateTimeOffset
        long milliseconds = (long)timeval.Seconds * 1000 + (long)timeval.MicroSeconds / 1000;
        DateTimeOffset time = DateTimeOffset.FromUnixTimeMilliseconds(milliseconds);

        // Convert to current system timezone
        TimeZoneInfo currentZone = TimeZoneInfo.Local;
        DateTimeOffset localTime = TimeZoneInfo.ConvertTime(time, currentZone);

        // Return formatted string in RFC3339
        return localTime.ToString("yyyy-MM-dd'T'HH:mm:ss.fffzzz");
    }

    private static string FormatMac(Packet packet, bool src)
    {
        //Loopback packet doesn't have Ethernet layer nor MAC address
        EthernetPacket? ethernetPacket = packet.Extract<EthernetPacket>();
        if (ethernetPacket == null)
        {
            return "NaN";
        }

        string rawMac;
        
        //Check if this should return source or destination MAC
        if (src)
        {
            rawMac = ethernetPacket.SourceHardwareAddress.ToString();
        }
        else
        {
            rawMac = ethernetPacket.DestinationHardwareAddress.ToString();
        }

        //Format MAC address
        for (int i = 2; i < rawMac.Length; i += 3)
        {
            rawMac = rawMac.Insert(i, ":");
        }
        return rawMac;
    }
    
    private static string FormatHexDump(byte[] bytes)
    {
        StringBuilder result = new();
        for (int i = 0; i < bytes.Length; i += 16)
        {
            //Byte offset
            result.Append($"{i:x4}: ");

            //Print bytes in this line
            for (int j = 0; j < 16; j++)
            {
                if (i + j < bytes.Length)
                {
                    result.Append($"{bytes[i + j]:x2} ");
                }
                else
                {
                    result.Append("   ");
                }

                // Insert additional space in the middle (wireshark style) 
                if (j == 7)
                {
                    result.Append(' ');
                }
            }

            result.Append(' ');

            //Print ASCII chars
            for (int j = 0; j < 16 && i + j < bytes.Length; j++)
            {
                // Insert additional space in the middle (wiresahrk style)
                if (j == 8)
                {
                    result.Append(' ');
                }

                //Non printable char as .
                if (bytes[i + j] < 32 || bytes[i + j] > 126)
                {
                    result.Append('.');
                }
                else
                {
                    result.Append((char)bytes[i + j]);
                }
            }

            //Next line
            result.AppendLine();
        }

        return result.ToString();
    }
    
}