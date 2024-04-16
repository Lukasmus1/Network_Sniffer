﻿using System.Net.NetworkInformation;
using SharpPcap;

namespace IPK_Project2;

public class ParseInterfaceClass(string interfaceName)
{
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

        ILiveDevice? res = devices.FirstOrDefault(o => o.Name == interfaceName);
        if (res == null)
        {
            Console.Error.WriteLine("Interface not found");
        }

        return res;
    }
    
}