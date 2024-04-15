using System.Net.NetworkInformation;
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
            foreach (ILiveDevice item in devices)
            {
                Console.WriteLine("Name: " + item.Name + "\nDescription: " + item.Description + "\n");
            }
            return null;
        }

        return devices.FirstOrDefault(o => o.Name == interfaceName);
    }
    
    public void ParseConnectionType(ushort port, bool tcp, bool udp)
    {
        
    }
}