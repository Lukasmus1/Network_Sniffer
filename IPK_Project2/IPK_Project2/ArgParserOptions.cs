using CommandLine;

namespace IPK_Project2;

public class ArgParserOptions
{
    [Option('i', "interface")]
    public string? Interface { get; set; }

    [Option('p')]
    public ushort? Port { get; set; }

    [Option("port-source")]
    public ushort? PortSource { get; set; }
    
    [Option("port-destination")]
    public ushort? PortDest { get; set; }
    
    [Option('t', "tcp")]
    public bool Tcp { get; set; }

    [Option('u', "udp")]
    public bool Udp { get; set; }

    [Option("arp")]
    public bool Arp { get; set; }
    
    [Option("icmp4")]
    public bool Icmp4 { get; set; }
    
    [Option("icmp6")]
    public bool Icmp6 { get; set; } 
    
    [Option("ndp")]
    public bool Ndp { get; set; }
    
    [Option("igmp")]
    public bool Igmp { get; set; }
    
    [Option("mld")]
    public bool Mld { get; set; }

    [Option('n', "num")] 
    public int Repeat { get; set; } = 1;

}