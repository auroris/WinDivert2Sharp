using System;
using System.Runtime.InteropServices;

namespace WinDivert2
{
    /*
    [StructLayout(LayoutKind.Sequential)]
    public struct WinDivertAddress_DataNetwork
    {
        public long Timestamp;
        public WinDivert.Layer Layer;
        public WinDivert.Event Event;
        public uint Sniffed;
        public uint Outbound;
        public uint Loopback;
        public uint Imposter;
        public uint IPv6;
        public uint IPChecksum;
        public uint TCPChecksum;
        public uint UDPChecksum;
        public uint Reserved1;
        public uint Reserved2;
        public uint IfIdx;
        public uint SubIfIdx;
    }
    
    [StructLayout(LayoutKind.Sequential)]
    public struct WinDivertAddress_DataSocket  //Also use for DATA_FLOW 
    {
        public long Timestamp;
        public WinDivert.Layer Layer;
        public WinDivert.Event Event;
        public uint Sniffed;
        public uint Outbound;
        public uint Loopback;
        public uint Imposter;
        public uint IPv6;
        public uint IPChecksum;
        public uint TCPChecksum;
        public uint UDPChecksum;
        public uint Reserved1;
        public uint Reserved2;
        public ulong EndpointId;
        public ulong ParentEndpointId;
        public uint ProcessId;
        [MarshalAsAttribute(UnmanagedType.ByValArray, SizeConst = 4)]
        public uint LocalAddr;
        [MarshalAsAttribute(UnmanagedType.ByValArray, SizeConst = 4)]
        public uint RemoteAddr;
        public ushort LocalPort;
        public ushort RemotePort;
        public byte Protocol;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct WinDivertAddress_DataReflect
    {
        public long Timestamp;
        public WinDivert.Layer Layer;
        public WinDivert.Event Event;
        public uint Sniffed;
        public uint Outbound;
        public uint Loopback;
        public uint Imposter;
        public uint IPv6;
        public uint IPChecksum;
        public uint TCPChecksum;
        public uint UDPChecksum;
        public uint Reserved1;
        public uint Reserved2;
        public long Timestamp2;
        public uint ProcessId;
        WinDivert.Layer Layer2;
        public ulong Flags;
        public short Priority;
    }*/
}