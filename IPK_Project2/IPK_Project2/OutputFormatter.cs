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
               "\nsrc IP: " + packet.Extract<IPPacket>().SourceAddress +
               "\ndst IP: " + packet.Extract<IPPacket>().DestinationAddress +
               "\nsrc port: " + ParsePort(packet, true) +
               "\ndst port: " + ParsePort(packet, false) +
               "\n" + FormatHexDump(rawCapture.GetPacket().Data);
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
            return "err";
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
    
    public static string FormatHexDump(byte[] bytes)
    {
        
    }
    
}