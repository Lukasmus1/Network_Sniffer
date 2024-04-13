using System.Text.RegularExpressions;
using SharpPcap;

namespace IPK_Project2;

public class Sniffer
{
    private string _interfaceName;
    private ushort _portSource, _portDest;
    private bool _tcp, _udp, _arp, _icmp4, _icmp6, _igmp, _mld;
    private int _repeat;
    
    public Sniffer(string interfaceName, ushort portSource, ushort portDest, bool tcp, bool udp, bool arp, bool icmp4, bool icmp6, bool igmp, bool mld, int repeat)
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

    public int Sniff()
    {
        ParseArguementsClass parser = new(_interfaceName, _portSource, _portDest, _tcp, _udp, _arp, _icmp4, _icmp6, _igmp, _mld, _repeat);
        CaptureDeviceList? devices = CaptureDeviceList.Instance;
        ILiveDevice? device;

        device = parser.ParseInterface(devices);
        if (device == null)
        {
            return 0;
        }



        return 0;
    }
}