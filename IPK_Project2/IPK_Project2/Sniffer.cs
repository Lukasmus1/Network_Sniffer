using System.Text.RegularExpressions;
using PacketDotNet;
using SharpPcap;

namespace IPK_Project2;

public class Sniffer
{
    private string _interfaceName;
    private ushort _portSource, _portDest;
    private bool _tcp, _udp, _arp, _icmp4, _icmp6, _igmp, _mld, _ndp;
    private int _repeat;
    
    private int _repeatCounter = 0;
    private bool _run = true;
    
    public Sniffer(string interfaceName, ushort portSource, ushort portDest, bool tcp, bool udp, bool arp, bool icmp4,
        bool icmp6, bool ndp, bool igmp, bool mld, int repeat)
    {
        _interfaceName = interfaceName;
        _portSource = portSource;
        _portDest = portDest;
        _ndp = ndp;
        _tcp = tcp;
        _udp = udp;
        _arp = arp;
        _icmp4 = icmp4;
        _icmp6 = icmp6;
        _igmp = igmp;
        _mld = mld;
        _repeat = repeat;
    }

    public int SniffingSetup()
    {
        ParseArguementsClass parser = new(_interfaceName, _portSource, _portDest, _tcp, _udp, _arp, _icmp4, _icmp6,
            _igmp, _mld, _repeat);
        CaptureDeviceList? devices = CaptureDeviceList.Instance;

        ILiveDevice? device = parser.ParseInterface(devices);
        if (device == null)
        {
            Console.WriteLine("The specified interface does not exist");
        }
        
        StartSniffing(device!);
        while (_run)
        {
            //Sleep to save CPU resources
            Thread.Sleep(100);
        }
        StopSniffing(device!);
        return 0;
    }

    private void StartSniffing(ILiveDevice device)
    {
        device.Open(DeviceModes.Promiscuous);
        device.OnPacketArrival += OnPacketArrival;
        device.StartCapture();
    }
    
    private void StopSniffing(ILiveDevice device)
    {
        device.StopCapture();
        device.Close();
    }
    
    private void OnPacketArrival(object sender, PacketCapture e)
    {
        Packet? packet = Packet.ParsePacket(e.GetPacket().LinkLayerType, e.GetPacket().Data);
        /*if (packet.HasPayloadPacket)
        {
            Console.WriteLine("lol");
        }*/

        if (FilterPacket(packet))
        {
            Console.WriteLine(OutputFormatter.FormatOutput(e));
            _repeatCounter++;
        }
    }

    private bool FilterPacket(Packet packet)
    {
        if (_repeatCounter < _repeat)
        {
            if (_tcp)
            {
                if (packet.Extract<TcpPacket>() == null)
                {
                    return false;
                }
                
                if ((_portSource != 0 && packet.Extract<TcpPacket>().SourcePort != _portSource) || (_portDest != 0 && packet.Extract<TcpPacket>().DestinationPort != _portDest))
                {
                    return false;
                }
            }
            else if (_udp)
            {
                if (packet.Extract<UdpPacket>() == null)
                {
                    return false;
                }
                
                if ((_portSource != 0 && packet.Extract<UdpPacket>().SourcePort != _portSource) || (_portDest != 0 && packet.Extract<UdpPacket>().DestinationPort != _portDest))
                {
                    return false;
                }
            }
        }
        else
        {
            _run = false;
            return false;
        }
        
        if (_icmp4 && packet.Extract<IcmpV4Packet>() == null)
        {
            return false;
        }
        
        if (_icmp6 && packet.Extract<IcmpV6Packet>() == null)
        {
            return false;
        }
        
        if (_arp && packet.Extract<ArpPacket>() == null)
        {
            return false;
        }
        
        if (_ndp && packet.Extract<NdpPacket>() == null)
        {
            return false;
        }
        
        if (_igmp && packet.Extract<IgmpV2Packet>() == null)
        {
            return false;
        }
        
        //MLD
        
        return true;
    }
}