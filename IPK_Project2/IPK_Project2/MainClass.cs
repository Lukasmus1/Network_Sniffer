using CommandLine;
using SharpPcap;

namespace IPK_Project2;

class MainClass
{
    static void Main(string[] args)
    {
        string interfaceName = string.Empty;
        ushort portSource = 0;
        ushort portDest = 0;
        bool tcp = false, udp = false, arp = false, icmp4 = false, icmp6 = false, igmp = false, mld = false;
        int repeat = 1;

        //Arg parser
        Parser parser = new();
        parser.ParseArguments<ArgParserOptions>(args)
            .WithParsed(o =>
            {
                interfaceName = o.Interface ?? "";
                tcp = o.Tcp;
                udp = o.Udp;
                arp = o.Arp;
                icmp4 = o.Icmp4;
                icmp6 = o.Icmp6;
                igmp = o.Igmp;
                mld = o.Mld;
                repeat = o.Repeat;

                if (o.Port != null)
                {
                    portSource = (ushort)o.Port;
                    portDest = (ushort)o.Port;
                }

                if (o.PortSource != null)
                {
                    portSource = (ushort)o.PortSource;
                }
                
                if (o.PortDest != null)
                {
                    portDest = (ushort)o.PortDest;
                }
            });
        
        //Start sniffing
        Sniffer sniffer = new(interfaceName, portSource, portDest, tcp, udp, arp, icmp4, icmp6, igmp, mld, repeat);
        sniffer.Sniff();
    }
}