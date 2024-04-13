using SharpPcap;

namespace IPK_Project2;

public class ParseArguementsClass(string interfaceName, ushort portSource, ushort portDest, bool tcp, bool udp, bool arp, bool icmp4, bool icmp6, bool igmp, bool mld, int repeat)
{
    private ushort _portSource = portSource;
    private ushort _portDest = portDest;
    private bool _tcp = tcp;
    private bool _udp = udp;
    private bool _arp = arp;
    private bool _icmp4 = icmp4;
    private bool _icmp6 = icmp6;
    private bool _igmp = igmp;
    private bool _mld = mld;
    private int _repeat = repeat;

    public ILiveDevice? ParseInterface(CaptureDeviceList devices)
    {
        if (interfaceName == string.Empty)
        {
            devices.ToList().ForEach(Console.WriteLine);
            return null;
        }
        
        foreach (ILiveDevice item in devices)
        {
            if (item.Description == interfaceName)
            {
                return item;
            }
        }

        return null;
    }
    
    public void ParseConnectionType()
    {
       
    }
}