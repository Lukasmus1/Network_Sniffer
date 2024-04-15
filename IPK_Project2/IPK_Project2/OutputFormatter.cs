using System.Text;
using PacketDotNet;
using SharpPcap;

namespace IPK_Project2;

public class OutputFormatter
{
    public static string FormatOutput(PacketCapture rawCapture)
    {
        Packet packet = Packet.ParsePacket(rawCapture.GetPacket().LinkLayerType, rawCapture.GetPacket().Data);
        return "timestamp: " + ConvertToRfc3339(rawCapture.GetPacket().Timeval) +
               "\nsrc MAC: " + FormatMac(((EthernetPacket)packet).SourceHardwareAddress.ToString()) +
               "\ndst MAC: " + FormatMac(((EthernetPacket)packet).DestinationHardwareAddress.ToString()) +
               "\nframe length: " + rawCapture.GetPacket().Data.Length +
               "\nsrc IP: " + ParseIpAddress(packet, true) +
               "\ndst IP: " + ParseIpAddress(packet, false) +
               "\nsrc port: " + ParsePort(packet, true) +
               "\ndst port: " + ParsePort(packet, false) +
               "\n" + FormatHexDump(rawCapture.GetPacket().Data);
    }

    private static string ParseIpAddress(Packet packet, bool src)
    {
        ArpPacket? arp = packet.Extract<ArpPacket>();
        if (arp == null)
        {
            return src ? packet.Extract<IPPacket>().SourceAddress.ToString() : packet.Extract<IPPacket>().DestinationAddress.ToString();
        }
        else
        {
            return src ? arp.SenderProtocolAddress.ToString() : arp.TargetProtocolAddress.ToString();
        }
    }
    
    private static string ParsePort(Packet packet, bool src)
    {
        if (packet.Extract<TcpPacket>() != null)
        {
            return src ? packet.Extract<TcpPacket>().SourcePort.ToString() : packet.Extract<TcpPacket>().DestinationPort.ToString();
        }
        else if (packet.Extract<UdpPacket>() != null)
        {
            return src ? packet.Extract<UdpPacket>().SourcePort.ToString() : packet.Extract<UdpPacket>().DestinationPort.ToString();
        }
        else
        {
            return "NaN";
        }
    }
    
    private static string ConvertToRfc3339(PosixTimeval timeval)
    {
        DateTimeOffset time = DateTimeOffset.FromUnixTimeSeconds((long)timeval.Seconds);      
        return time.ToString("yyyy-MM-dd'T'HH:mm:sszzz");
    }

    private static string FormatMac(string rawMac)
    {
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
            }

            //Print ASCII chars
            for (int j = 0; j < 16 && i + j < bytes.Length; j++)
            {
                //Non printable char as .
                if (bytes[i + j] < 32 || bytes[i + j] > 127) 
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