using System.Text.RegularExpressions;
using PacketDotNet;
using SharpPcap;

namespace IPK_Project2;

public class Sniffer
{
    private string _interfaceName;
    private ushort _portSource, _portDest;
    private bool _tcp, _udp, _arp, _icmp4, _icmp6, _igmp, _mld;
    private int _repeat;
    
    private int _repeatCounter = 0;
    private bool _run = true;
    
    public Sniffer(string interfaceName, ushort portSource, ushort portDest, bool tcp, bool udp, bool arp, bool icmp4,
        bool icmp6, bool igmp, bool mld, int repeat)
    {
        this._interfaceName = interfaceName;
        this._portSource = portSource;
        this._portDest = _portDest;
        this._tcp = tcp;
        this._udp = udp;
        this._arp = arp;
        this._icmp4 = icmp4;
        this._icmp6 = icmp6;
        this._igmp = igmp;
        this._mld = mld;
        this._repeat = repeat;
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
        if (_repeatCounter != _repeat)
        {
            Console.WriteLine(OutputFormatter.FormatOutput(e));
            _repeatCounter++;
        }
        else
        {
            _run = false;
        }
    }

}