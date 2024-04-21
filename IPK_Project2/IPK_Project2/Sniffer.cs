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

    public void SniffingSetup()
    {
        ParseInterfaceClass parser = new(_interfaceName);
        CaptureDeviceList? devices = CaptureDeviceList.Instance;

        //Parsing of interface argument
        ILiveDevice? device = parser.ParseInterface(devices);
        if (device == null)
        {
            return;
        }

        StartSniffing(device);
        
        //Loop to prevent program from ending prematurely
        while (_run)
        {
            //Sleep to save CPU resources
            Thread.Sleep(1);
        }

        StopSniffing(device);
    }

    private void StartSniffing(ICaptureDevice device)
    {
        device.Open(DeviceModes.Promiscuous);
        device.OnPacketArrival += OnPacketArrival;
        device.StartCapture();
    }

    private void StopSniffing(ICaptureDevice device)
    {
        device.StopCapture();
        device.Close();
    }

    private void OnPacketArrival(object sender, PacketCapture e)
    {
        Packet? packet = Packet.ParsePacket(e.GetPacket().LinkLayerType, e.GetPacket().Data);

        //Filtering packets
        if (!FilterPacket(packet))
        {
            return;
        }
        Console.WriteLine(OutputFormatter.FormatOutput(e));
        _repeatCounter++;
    }

    private bool FilterPacket(Packet packet)
    {
        if (_repeatCounter >= _repeat)
        {
            _run = false;
            return false;
        }

        TcpPacket? tcpPacket = packet.Extract<TcpPacket>();
        UdpPacket? udpPacket = packet.Extract<UdpPacket>();
        if (_tcp)
        {
            if (tcpPacket != null)
            {
                //Port parsing
                //Port 0 is a wildcard for any port
                if (!(_portSource == 0 && tcpPacket.SourcePort != _portSource && _portDest != 0 && tcpPacket.DestinationPort != _portDest))
                {
                    return true;
                }
            }
        }
        else if (_udp)
        {
            if (udpPacket != null)
            {
                //Port parsing
                //Port 0 is a wildcard for any port
                if (!(_portSource == 0 && udpPacket.SourcePort != _portSource && _portDest != 0 && udpPacket.DestinationPort != _portDest))
                {
                    return true;
                }
            }
        }
        
        //ICMP4 filter
        IcmpV4Packet? icmpv4Packet = packet.Extract<IcmpV4Packet>();
        if (_icmp4 && icmpv4Packet != null)
        {
            return true;
        }

        //ICMP6 filter
        IcmpV6Packet? icmpv6Packet = packet.Extract<IcmpV6Packet>();
        if (_icmp6)
        {
            if (icmpv6Packet != null && !(icmpv6Packet.Type != IcmpV6Type.EchoRequest && icmpv6Packet.Type != IcmpV6Type.EchoReply))
            {
                return true;
            }
        }

        //ARP filter
        ArpPacket? arpPacket = packet.Extract<ArpPacket>();
        if (_arp && arpPacket != null)
        {
            return true;
        }

        //NDP filter
        NdpPacket? ndpPacket = packet.Extract<NdpPacket>();
        if (_ndp && ndpPacket != null)
        {
            return true;
        }

        //IGMP filter
        IgmpV2Packet? igmpPacket = packet.Extract<IgmpV2Packet>();
        if (_igmp && igmpPacket != null)
        {
            return true;
        }

        //MLD filter
        IcmpV6Packet? packetV6 = null;
        if (arpPacket == null)
        {
            if (_mld)
            {
                if (packet.Extract<IPPacket>() != null)
                {
                    packetV6 = packet.Extract<IcmpV6Packet>();
                    if (packetV6 != null)
                    {
                        switch ((int)packetV6.Type)
                        {
                            case 130:
                            case 131:
                            case 132:
                            case 143:
                                return true;
                        }
                    }
                }
            }
        }

        if (tcpPacket == null && udpPacket == null && arpPacket == null && icmpv4Packet == null &&
             icmpv6Packet == null && igmpPacket == null && packetV6 == null && ndpPacket == null)
        {
            return false;
        }
        
        if (!_tcp && !_udp && !_arp && !_icmp4 && !_icmp6 && !_igmp && !_mld && !_ndp)
        {
            return true;
        }
        
        return false;
    }

    public void EndProgram(object? sender, ConsoleCancelEventArgs e)
    {
        e.Cancel = true;
        _run = false;
    }
}