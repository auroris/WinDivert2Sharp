using System;
using System.ComponentModel;
using System.IO;
using System.Runtime.InteropServices;
using System.ServiceProcess;
using WinDivert2.Exceptions;

namespace WinDivert2
{
	public class WinDivert
	{
		static WinDivert()
		{
			String path = Path.Combine(Path.GetDirectoryName(new Uri(typeof(WinDivert).Assembly.CodeBase).LocalPath),
				Environment.Is64BitProcess ? "x64" : "x86");
			if (!SetDllDirectory(path))
			{
				throw new Win32Exception();
			}
		}

		[DllImport("kernel32.dll", CharSet = CharSet.Auto, SetLastError = true)]
		private static extern bool SetDllDirectory(string path);

		/// <summary>
		/// Opens a WinDivert handle for the given filter. Unless otherwise specified by flags, any packet or event that matches the filter will be diverted to the handle. Diverted packets/events can be read by the application with WinDivertRecv().
		///
		/// A typical application is only interested in a subset of all network traffic or events.In this case the filter should match as closely as possible to the subset of interest. This avoids unnecessary overheads introduced by diverting packets to the user-mode application. See the filter language section for more information. 
		///
		/// Different WinDivert handles can be assigned different priorities by the priority parameter. Packets are diverted to higher priority handles before lower priority handles. Packets injected by a handle are then diverted to the next priority handle, and so on, provided the packet matches the handle's filter. A packet is only diverted once per priority level, so handles should not share priority levels unless they use mutually exclusive filters. Otherwise it is not defined which handle will receive the packet first. Higher priority values represent higher priorities, with WINDIVERT_PRIORITY_HIGHEST being the highest priority, 0 the middle (and a good default) priority, and WINDIVERT_PRIORITY_LOWEST the lowest priority. 
		/// 
		/// Note that any combination of (WinDivertFlag.SNIFF | WinDivertFlag.DROP) or (WinDivertFlag.RECV_ONLY | WinDivertFlag.SEND_ONLY) are considered invalid. Some layers have mandatory flags.
		/// </summary>
		/// <param name="filter">A packet filter string specified in the WinDivert filter language.</param>
		/// <param name="layer">The layer.</param>
		/// <param name="priority">The priority of the handle.</param>
		/// <param name="flags">Additional flags.</param>
		/// <remarks>
		/// Different WinDivert handles can be assigned different priorities by the priority parameter. Packets are diverted to higher priority handles before lower priority handles. Packets injected by a handle are then diverted to the next priority handle, and so on, provided the packet matches the handle's filter. A packet is only diverted once per priority level, so handles should not share priority levels unless they use mutually exclusive filters. Otherwise it is not defined which handle will receive the packet first. Higher priority values represent higher priorities, with WINDIVERT_PRIORITY_HIGHEST being the highest priority, 0 the middle (and a good default) priority, and WINDIVERT_PRIORITY_LOWEST the lowest priority. 
		/// </remarks>
		/// <returns>A valid WinDivert handle on success, or INVALID_HANDLE_VALUE if an error occurred. Use GetLastError() to get the reason for the error.</returns>
		[DllImport("WinDivert.dll", EntryPoint = "WinDivertOpen", CallingConvention = CallingConvention.Cdecl, SetLastError = true)]
		public static extern IntPtr _WinDivertOpen([MarshalAs(UnmanagedType.LPStr)] string filter, Layer layer, short priority, Flag flags);

		/// <summary>
		/// This operation causes all or part of a WinDivert handle to be shut down. Note that previously queued packets can still be received after WINDIVERT_SHUTDOWN_RECV. When the packet queue is empty, WinDivertRecv() will fail with ERROR_NO_DATA. 
		/// </summary>
		/// <param name="handle">A valid WinDivert handle created by WinDivertOpen().</param>
		/// <param name="how">A WINDIVERT_SHUTDOWN value to indicate how the handle should be shutdown.</param>
		/// <returns>TRUE if successful, FALSE if an error occurred. Use GetLastError() to get the reason for the error. </returns>
		[DllImport("WinDivert.dll", EntryPoint = "WinDivertShutdown", CallingConvention = CallingConvention.Cdecl, SetLastError = true)]
		public static extern bool _WinDivertShutdown(IntPtr handle, Shutdown how);

		/// <summary>
		/// Closes a WinDivert handle created by WinDivertOpen().
		/// </summary>
		/// <param name="handle">A valid WinDivert handle created by WinDivertOpen().</param>
		/// <returns>TRUE if successful, FALSE if an error occurred. Use GetLastError() to get the reason for the error. </returns>
		[DllImport("WinDivert.dll", EntryPoint = "WinDivertClose", CallingConvention = CallingConvention.Cdecl, SetLastError = true)]
		public static extern bool _WinDivertClose(IntPtr handle);

		/// <summary>
		/// Sets a WinDivert parameter.
		/// </summary>
		/// <param name="handle">A valid WinDivert handle created by WinDivertOpen().</param>
		/// <param name="param">A WinDivert parameter name.</param>
		/// <param name="value">The parameter's new value.</param>
		/// <returns>TRUE if successful, FALSE if an error occurred. Use GetLastError() to get the reason for the error.</returns>
		[DllImport("WinDivert.dll", EntryPoint = "WinDivertSetParam", CallingConvention = CallingConvention.Cdecl, SetLastError = true)]
		public static extern bool _WinDivertSetParam(IntPtr handle, Param param, ulong value);

		/// <summary>
		/// Gets a WinDivert parameter.
		/// </summary>
		/// <param name="handle">A valid WinDivert handle created by WinDivertOpen().</param>
		/// <param name="param">A WinDivert parameter name.</param>
		/// <param name="value">The parameter's current value.</param>
		/// <returns>TRUE if successful, FALSE if an error occurred. Use GetLastError() to get the reason for the error.</returns>
		[DllImport("WinDivert.dll", EntryPoint = "WinDivertGetParam", CallingConvention = CallingConvention.Cdecl, SetLastError = true)]
		public static extern bool _WinDivertGetParam(IntPtr handle, Param param, out ulong value);

		/// <summary>
		/// Receives a single captured packet/event matching the filter passed to WinDivertOpen(). The received packet/event is guaranteed to match the filter. Only NETWORK, NETWORK_FORWARD and REFLECT can capture packets/data.
		///
		/// For layers that do support capturing, the captured packet/data will be written to the pPacket buffer. If non-NULL, then the total number of bytes written to pPacket will be written to pRecvLen. If the pPacket buffer is too small, the packet will be truncated and the operation will fail with the ERROR_INSUFFICIENT_BUFFER error code. This error can be ignored if the application only intends to receive part of the packet, e.g., the IP headers only. For layers that do not capture packets/data, the pPacket parameter should be NULL and packetLen should be zero.
		///
		/// If non-NULL, the address of the packet/event will be written to the pAddr buffer.
		//
		//An application should call WinDivertRecv() as soon as possible after a successful call to WinDivertOpen(). When a WinDivert handle is open, any packet/event that matches the filter will be captured and queued until handled by WinDivertRecv(). Packets/events are not queued indefinitely, and if not handled in a timely manner, data may be lost.The amount of time a packet/event is queued can be controlled using the WinDivertSetParam() function.
		//
		// Captured packets are guaranteed to have correct checksums or have the corresponding * Checksum flag unset(see WINDIVERT_ADDRESS).
		//
		// WinDivertRecv() should not be used on any WinDivert handle created with the WINDIVERT_FLAG_DROP set.
		/// </summary>
		/// <param name="handle">A valid WinDivert handle created by WinDivertOpen().</param>
		/// <param name="pPacket">An optional buffer for the captured packet.</param>
		/// <param name="packetLen">The length of the pPacket buffer.</param>
		/// <param name="pRecvLen">The total number of bytes written to pPacket. Can be NULL if this information is not required.</param>
		/// <param name="pAddr">An optional buffer for the address of the captured packet/event.</param>
		/// <returns>TRUE if a packet/event was successfully received, or FALSE if an error occurred. Use GetLastError() to get the reason for the error. </returns>
		[DllImport("WinDivert.dll", EntryPoint = "WinDivertRecv", CallingConvention = CallingConvention.Cdecl, SetLastError = true)]
		public static extern bool _WinDivertRecv(IntPtr handle, IntPtr pPacket, uint packetLen, ref uint pRecvLen, ref Address address);

		#region Constants
		/// <summary>
		/// Maximum priority for a filter when calling WinDivertOpen
		/// </summary>
		public static readonly short PRIORITY_HIGHEST = 30000;
		/// <summary>
		/// Lowest possible priority for a filter when calling WinDivertOpen
		/// </summary>
		public static readonly short PRIORITY_LOWEST = (Int16)(-PRIORITY_HIGHEST);
		/// <summary>
		/// An invalid handle
		/// </summary>
		public static readonly IntPtr INVALID_HANDLE_VALUE = new IntPtr(-1);
		/// <summary>
		/// Default length for the packet queue, # of packets
		/// </summary>
		public static readonly ulong PARAM_QUEUE_LENGTH_DEFAULT = 4096;
		/// <summary>
		/// Minimum size for the packet queue, # of packets
		/// </summary>
		public static readonly ulong PARAM_QUEUE_LENGTH_MIN = 32;
		/// <summary>
		///  Maximum size for the packet queue, # of packets
		/// </summary>
		public static readonly ulong PARAM_QUEUE_LENGTH_MAX = 16384;
		/// <summary>
		/// Default amount of time a packet can remain in the queue before it is dropped, 2 seconds
		/// </summary>
		public static readonly ulong PARAM_QUEUE_TIME_DEFAULT = 2000;
		/// <summary>
		/// Minimum amount of time a packet can remain in the queue before it is dropped, 100 milliseconds
		/// </summary>
		public static readonly ulong PARAM_QUEUE_TIME_MIN = 100;
		/// <summary>
		/// Maximum amount of time a packet can remain in the queue before it is dropped, 16 seconds
		/// </summary>
		public static readonly ulong PARAM_QUEUE_TIME_MAX = 16000;
		/// <summary>
		/// Default size of the packet queue in bytes, 4 megabytes
		/// </summary>
		public static readonly ulong PARAM_QUEUE_SIZE_DEFAULT = 4194304;
		/// <summary>
		/// Minimum size of the packet queue in bytes, 65 kilobytes
		/// </summary>
		public static readonly ulong PARAM_QUEUE_SIZE_MIN = 65535;
		/// <summary>
		/// Maximum size of the packet queue in bytes, 32 megabytes
		/// </summary>
		public static readonly ulong PARAM_QUEUE_SIZE_MAX = 33554432;
		#endregion

		#region Enums
		/// <summary>
		/// Represents which part of the networking layer a WinDivert handle is operating on.
		/// </summary>
		public enum Layer : uint
		{
			/// <summary>
			/// Network packets to/from the local machine. This is the default layer. 
			/// </summary>
			NETWORK = 0,

			/// <summary>
			/// Network packets passing through the local machine. 
			/// </summary>
			NETWORK_FORWARD = 1,

			/// <summary>
			/// Network flow established/deleted events. 
			/// </summary>
			FLOW = 2,

			/// <summary>
			/// Socket operation events.
			/// </summary>
			SOCKET = 3,

			/// <summary>
			/// WinDivert handle events. 
			/// </summary>
			REFLECT = 4
		}

		public enum Flag : ulong
		{
			/// <summary>
			/// No flags.
			/// </summary>
			NONE = 0,
			/// <summary>
			/// This flag opens the WinDivert handle in packet sniffing mode. In packet sniffing mode the original packet is not dropped-and-diverted (the default) but copied-and-diverted. This mode is useful for implementing packet sniffing tools similar to those applications that currently use Winpcap. 
			/// </summary>
			SNIFF = 0x0001,
			/// <summary>
			/// This flag indicates that the user application does not intend to read matching packets with WinDivertRecv(), instead the packets should be silently dropped. This is useful for implementing simple packet filters using the WinDivert filter language. 
			/// </summary>
			DROP = 0x0002,
			/// <summary>
			/// This flags forces the handle into "receive only" mode which effectively disables WinDivertSend(). This means that it is possible to block/capture packets or events but not inject them. 
			/// </summary>
			RECV_ONLY = 0x0004,
			/// <summary>
			/// Alias for RECV_ONLY
			/// </summary>
			READ_ONLY = Flag.RECV_ONLY,
			/// <summary>
			/// This flags forces the handle into "send only" mode which effectively disables WinDivertRecv(). This means that it is possible to inject packets or events, but not block/capture them. 
			/// </summary>
			SEND_ONLY = 0x0008,
			/// <summary>
			/// Alias for SEND_ONLY
			/// </summary>
			WRITE_ONLY = Flag.SEND_ONLY,
			/// <summary>
			/// This flags causes WinDivertOpen() to fail with ERROR_SERVICE_DOES_NOT_EXIST if the WinDivert driver is not already installed. This flag is useful for querying the WinDivert state using a WINDIVERT_LAYER_REFLECT handle. 
			/// </summary>
			NO_INSTALL = 0x0010,
			/// <summary>
			/// If set, the handle will capture inbound IP fragments, but not inbound reassembled IP packets. Otherwise, if not set (the default), the handle will capture inbound reassembled IP packets, but not inbound IP fragments. This flag only affects inbound packets at the WINDIVERT_LAYER_NETWORK layer, else the flag is ignored. 
			/// </summary>
			FRAGMENTS = 0x0020
		}

		public enum Shutdown : ushort
		{
			/// <summary>
			/// Stop new packets being queued for WinDivertRecv(). 
			/// </summary>
			RECV = 0x1,
			/// <summary>
			/// Stop new packets being injected via WinDivertSend(). 
			/// </summary>
			SEND = 0x2,
			/// <summary>
			/// Equivalent to (WinDivertShutdown.RECV | WinDivertShutdown.SEND). 
			/// </summary>
			BOTH = 0x3
		}

		public enum Param : uint
		{
			/// <summary>
			/// Sets the maximum length of the packet queue for WinDivertRecv(). The default value is PARAM_QUEUE_LENGTH_DEFAULT, the minimum is PARAM_QUEUE_LENGTH_MIN, and the maximum is PARAM_QUEUE_LENGTH_MAX. 
			/// </summary>
			QUEUE_LENGTH = 0,
			/// <summary>
			/// Sets the minimum time, in milliseconds, a packet can be queued before it is automatically dropped. Packets cannot be queued indefinitely, and ideally, packets should be processed by the application as soon as is possible. Note that this sets the minimum time a packet can be queued before it can be dropped. The actual time may be exceed this value. Currently the default value is PARAM_QUEUE_TIME_DEFAULT, the minimum is PARAM_QUEUE_TIME_MIN, and the maximum is PARAM_QUEUE_TIME_MAX. 
			/// </summary>
			QUEUE_TIME = 1,
			/// <summary>
			/// Sets the maximum number of bytes that can be stored in the packet queue for WinDivertRecv(). Currently the default value is PARAM_QUEUE_SIZE_DEFAULT, the minimum is PARAM_QUEUE_SIZE_MIN, and the maximum is PARAM_QUEUE_SIZE_MAX. 
			/// </summary>
			QUEUE_SIZE = 2,
			/// <summary>
			/// Read only: Returns the major version of the driver. 
			/// </summary>
			VERSION_MAJOR = 3,
			/// <summary>
			/// Read only: Returns the minor version of the driver. 
			/// </summary>
			VERSION_MINOR = 4
		}

		public enum Event : uint
		{
			/// <summary>
			/// For Layer.NETWORK and Layer.NETWORK_FORWARD: A new network packet.
			/// </summary>
			NETWORK_PACKET = 0,
			/// <summary>
			/// For Layer.FLOW: A new flow is created. 
			/// </summary>
			FLOW_ESTABLISHED = 1,
			/// <summary>
			/// For Layer.FLOW: An old flow is deleted. 
			/// </summary>
			FLOW_DELETED = 2,
			/// <summary>
			/// For Layer.SOCKET: A bind() operation. 
			/// </summary>
			SOCKET_BIND = 3,
			/// <summary>
			/// For Layer.SOCKET: A connect() operation.
			/// </summary>
			SOCKET_CONNECT = 4,
			/// <summary>
			/// For Layer.SOCKET: A listen() operation. 
			/// </summary>
			SOCKET_LISTEN = 5,
			/// <summary>
			/// For Layer.SOCKET: An accept() operation. 
			/// </summary>
			SOCKET_ACCEPT = 6,
			/// <summary>
			/// For Layer.SOCKET: A socket endpoint is closed. This corresponds to a previous binding being released, or an established connection being terminated. The event cannot be blocked. 
			/// </summary>
			SOCKET_CLOSE = 7,
			/// <summary>
			/// For Layer.REFLECT: A new WinDivert handle was opened. 
			/// </summary>
			REFLECT_OPEN = 8,
			/// <summary>
			/// FOr Layer.REFLECT: An old WinDivert handle was closed. 
			/// </summary>
			REFLECT_CLOSE = 9
		}
		#endregion

		#region Structs
		/// <summary>
		/// The Address structure represents the "address" of a captured or injected packet. The address includes the packet's timestamp, layer, event, flags, and layer-specific data. All fields are set by WinDivertRecv() when the packet/event is captured. Only some fields are used by WinDivertSend() when a packet is injected. 
		/// </summary>
		[StructLayout(LayoutKind.Explicit, Size=74)]
		public struct Address
		{
			/* Common */
			/// <summary>Indicates when the packet/event was first captured by WinDivert. It uses the same clock as QueryPerformanceCounter().</summary>
			[FieldOffset(0)] public long Timestamp;
			[FieldOffset(8)] private byte _bLayer;
			[FieldOffset(9)] private byte _bEvent;
			[FieldOffset(10)] private byte _bFlags;
			[FieldOffset(11)] private byte Reserved1;
			[FieldOffset(12)] private uint Reserved2;

			/* Network and Network_Forward */
			/// <summary>This field is only valid when using WinDivert.Layer.NETWORK and WinDivert.Layer.NETWORK_FORWARD. The Network.IfIdx/Network.SubIfIdx indicate the packet's network adapter (a.k.a. interface) index. These values are ignored for outbound packets. </summary>
			[FieldOffset(16)] public uint IfIdx;
			/// <summary>This field is only valid when using WinDivert.Layer.NETWORK and WinDivert.Layer.NETWORK_FORWARD. The Network.IfIdx/Network.SubIfIdx indicate the packet's network adapter (a.k.a. interface) index. These values are ignored for outbound packets. </summary>
			[FieldOffset(60)] public uint SubIfIdx;

			/* Socket and Flow */
			/// <summary>This field is only valid when using WinDivert.Layer.FLOW and WinDivert.Layer.SOCKET. The endpoint ID of the flow.</summary>
			[FieldOffset(16)] public ulong EndpointId;
			/// <summary> This field is only valid when using WinDivert.Layer.FLOW and WinDivert.Layer.SOCKET. The parent endpoint ID of the flow.</summary>
			[FieldOffset(24)] public ulong ParentEndpointId;
			/// <summary>This field is only valid when using WinDivert.Layer.FLOW and WinDivert.Layer.SOCKET. The ProcessId is the ID of the process that created the flow (for outbound), or receives the flow (for inbound).</summary>
			[FieldOffset(32)] public uint ProcessId;
			/// <summary>This field is only valid when using WinDivert.Layer.FLOW and WinDivert.Layer.SOCKET. LocalAddr will be IPv4-mapped IPv6 address, e.g. the IPv4 address X.Y.Z.W will be represented by ::ffff:X.Y.Z.W. IPv6 addresses are 16-bytes long (represented as 4x uint32's)</summary>
			[FieldOffset(36)] public uint LocalAddr1;
			[FieldOffset(40)] public uint LocalAddr2;
			[FieldOffset(44)] public uint LocalAddr3;
			[FieldOffset(48)] public uint LocalAddr4;
			/// <summary>This field is only valid when using WinDivert.Layer.FLOW and WinDivert.Layer.SOCKET. RemoteAddr will be IPv4-mapped IPv6 address, e.g. the IPv4 address X.Y.Z.W will be represented by ::ffff:X.Y.Z.W. IPv6 addresses are 16-bytes long (represented as 4x uint32's)</summary>
			[FieldOffset(52)] public uint RemoteAddr1;
			[FieldOffset(56)] public uint RemoteAddr2;
			[FieldOffset(60)] public uint RemoteAddr3;
			[FieldOffset(64)] public uint RemoteAddr4;
			/// <summary>This field is only valid when using WinDivert.Layer.FLOW and WinDivert.Layer.SOCKET. LocalPort is the local port associated with the connection.</summary>
			[FieldOffset(68)] public ushort LocalPort;
			/// <summary>This field is only valid when using WinDivert.Layer.FLOW and WinDivert.Layer.SOCKET. RemotePort is the local port associated with the connection.</summary>
			[FieldOffset(70)] public ushort RemotePort;
			/// <summary>This field is only valid when using WinDivert.Layer.FLOW and WinDivert.Layer.SOCKET. Protocol is the type of packet.</summary>
			[FieldOffset(72)] public Protocol Protocol;

			/* Reflect */
			/// <summary>This field is only valid when using WinDivert.Layer.REDIRECT. A timestamp indicating when the handle was opened.</summary>
			[FieldOffset(16)] public long ReflectTimestamp;
			/// <summary>This field is only valid when using WinDivert.Layer.REDIRECT. The ID of the process that opened the handle.</summary>
			[FieldOffset(24)] public uint ReflectProcessId;
			/// <summary>This field is only valid when using WinDivert.Layer.REDIRECT. The WinDivertOpen() parameters of the opened handle.</summary>
			[FieldOffset(28)] WinDivert.Layer ReflectLayer;
			/// <summary>This field is only valid when using WinDivert.Layer.REDIRECT. The WinDivertOpen() parameters of the opened handle.</summary>
			[FieldOffset(32)] public WinDivert.Flag ReflectFlags;
			/// <summary>This field is only valid when using WinDivert.Layer.REDIRECT. The WinDivertOpen() parameters of the opened handle.</summary>
			[FieldOffset(40)] public short ReflectPriority;

			/* Accessor methods for bitpacked fields */
			/// <summary>The Layer indicates the layer parameter (WinDivert.Layer.*) that was passed to WinDivertOpen(). It is included in the address to make the structure self-contained. </summary>
			public WinDivert.Layer Layer
			{
				get => (WinDivert.Layer)Convert.ToUInt32(_bLayer);
				set => _bLayer = (byte)value;
			}

			/// <summary>The Event indicates the layer-specific event (WinDivert.Event.*) that was captured.</summary>
			public WinDivert.Event Event
			{
				get => (WinDivert.Event)Convert.ToUInt32(_bEvent);
				set => _bEvent = (byte)value;
			}

			/// <summary>The Sniffed flag is set for packets that have "sniffed" (i.e., not blocked), cleared otherwise</summary>
			public bool Sniffed
			{
				get => Get(Bitfield.Sniffed);
				set => Set(Bitfield.Sniffed, value);
			}

			/// <summary>The Outbound flag is set for outbound packets/events, and is cleared for inbound or direction-less packets/events.</summary>
			public bool Outbound
			{
				get => Get(Bitfield.Outbound);
				set => Set(Bitfield.Outbound, value);
			}

			/// <summary>The Loopback flag is set for loopback packets. Note that Windows considers any packet originating from, and destined to, the current machine to be a loopback packet, so loopback packets are not limited to localhost addresses. Note that WinDivert considers loopback packets to be outbound only, and will not capture loopback packets on the inbound path.</summary>
			public bool Loopback
			{
				get => Get(Bitfield.Loopback);
				set => Set(Bitfield.Loopback, value);
			}

			/// <summary>The Impostor flag is set for impostor packets. An impostor packet is any packet injected by another driver rather than originating from the network or Windows TCP/IP stack. Impostor packets are problematic since they can cause infinite loops, where a packet injected by WinDivertSend() is captured again by WinDivertRecv(). For more information, see WinDivertSend().</summary>
			public bool Imposter
			{
				get => Get(Bitfield.Imposter);
				set => Set(Bitfield.Imposter, value);
			}

			/// <summary>The IPv6 flag is set for IPv6 packets/events, and cleared for IPv4 packets/events.</summary>
			public bool IPv6
			{
				get => Get(Bitfield.IPv6);
				set => Set(Bitfield.IPv6, value);
			}

			/// <summary>The IPChecksum flag indicate whether the packet has a valid checksum or not. When IP/TCP/UDP checksum offloading is enabled, it is possible that captured packets do not have valid checksums. Invalid checksums may be arbitrary values.</summary>
			public bool IPChecksum
			{
				get => Get(Bitfield.IPChecksum);
				set => Set(Bitfield.IPChecksum, value);
			}

			/// <summary>The TCPChecksum flag indicate whether the packet has a valid checksum or not. When IP/TCP/UDP checksum offloading is enabled, it is possible that captured packets do not have valid checksums. Invalid checksums may be arbitrary values.</summary>
			public bool TCPChecksum
			{
				get => Get(Bitfield.TCPChecksum);
				set => Set(Bitfield.TCPChecksum, value);
			}

			/// <summary>The UDPChecksum flag indicate whether the packet has a valid checksum or not. When IP/TCP/UDP checksum offloading is enabled, it is possible that captured packets do not have valid checksums. Invalid checksums may be arbitrary values. </summary>
			public bool UDPChecksum
			{
				get => Get(Bitfield.UDPChecksum);
				set => Set(Bitfield.UDPChecksum, value);
			}

			/// <summary>Bitfield positions for items in the _bFlags bit array.</summary>
			private enum Bitfield : byte
			{
				Sniffed = 1 << 0,
				Outbound = 1 << 1,
				Loopback = 1 << 2,
				Imposter = 1 << 3,
				IPv6 = 1 << 4,
				IPChecksum = 1 << 5,
				TCPChecksum = 1 << 6,
				UDPChecksum = 1 << 7
			}

			/// <summary>Set or unset a bit in the _bFlags bitfield.</summary>
			private void Set(Bitfield bit, bool b)
			{
				_bFlags = (byte)(b ? _bFlags | (byte)bit : _bFlags & (byte)~bit);
			}

			/// <summary>Get the flag of a bit in the _bFlags bitfield.</summary>
			private bool Get(Bitfield bit)
			{
				return (_bFlags & (byte)bit) != 0;
			}
		}

		/// <summary>
		/// IPv4 header definition. 
		/// </summary>
		[StructLayout(LayoutKind.Sequential)]
		public struct IPHeader
		{
			private byte _hdr;
			public byte TOS;
			public ushort Length;
			public ushort Id;
			private ushort FragOff0;
			public byte TTL;
			public Protocol Protocol;
			public ushort Checksum;
			public uint SrcAddr;
			public uint DstAddr;

			/// <summary>
			/// Internet Header Length (IHL) contains the size of the IPv4 header, it has 4 bits that specify the number of 32-bit words in the header. The minimum value for this field is 5 and the maximum size is 15.
			/// </summary>
			public int HdrLength
			{
				get => _hdr >> 4;
				set => _hdr = (byte)((_hdr & ~0xf0u) | ((byte)(value << 4) & 0xf0u));
			}

			/// <summary>
			/// The first header field in an IP packet is the four-bit version field. For IPv4, this is always equal to 4.
			/// </summary>
			public int Version
			{
				get => _hdr & 0x0f;
				set => _hdr = (byte)((_hdr & ~0x0fu) | ((byte)value & 0x0fu));
			}

			/// <summary>
			/// The fragment offset field is measured in units of eight-byte blocks. It is 13 bits long and specifies the offset of a particular fragment relative to the beginning of the original unfragmented IP datagram. The first fragment has an offset of zero.
			/// </summary>
			public ushort FragmentOffset
			{
				get => (ushort)(FragOff0 & 0xFF1Fu);
				set => FragOff0 = (ushort)((FragOff0 & 0x00E0u) | (value & 0xFF1Fu));
			}

			/// <summary>
			/// The original packet was fragmented, and there are more fragments to come. For fragmented packets, all fragments except the last have this flag set. The last fragment has a non-zero Fragment Offset, differentiating it from an unfragmented packet.
			/// </summary>
			public bool MoreFragments
			{
				get => (FragOff0 & 0x0020) != 0;
				set => FragOff0 = (ushort)((FragOff0 & 0xFFDFu) | (Convert.ToUInt16(value) & 0x0001u) << 5);
			}

			/// <summary>
			/// If the DontFragment flag is set, and fragmentation is required to route the packet, then the packet is dropped.
			/// </summary>
			public bool DontFragment
			{
				get => (FragOff0 & 0x0040u) != 0;
				set => FragOff0 = (ushort)((FragOff0 & 0xFFBFu) | (Convert.ToUInt16(value) & 0x0001u) << 6);
			}
		}

		/// <summary>
		/// IPv6 header definition. 
		/// </summary>
		[StructLayout(LayoutKind.Sequential)]
		public struct IPv6Header
		{
			[MarshalAs(UnmanagedType.ByValArray, SizeConst = 4)]
			private byte[] _hdr;
			public ushort Length;
			public byte NextHdr;
			public byte HopLimit;
			[MarshalAs(UnmanagedType.ByValArray, SizeConst = 4)]
			public uint[] SrcAddr;
			[MarshalAs(UnmanagedType.ByValArray, SizeConst = 4)]
			public uint[] DstAddr;

			/// <summary>The four-bit version field. For IPv6, this is always equal to 6.</summary>
			public uint Version
			{
				get => (uint)(_hdr[0] & 0x0fu);
				set => _hdr[0] = (byte)((_hdr[0] & ~0x0fu) | ((byte)value & 0x0fu)); // Assignment to the right-half of the first byte
			}

			public uint TrafficClass
			{ 
				get => (uint)((_hdr[0] & ~0x0f) | (_hdr[1] & ~0xf0));
				set
				{
					_hdr[0] = (byte)((_hdr[0] & ~0xf0u) | ((byte)value & 0xf0u)); // Assignment to the left-half of the first byte
					_hdr[1] = (byte)((_hdr[1] & ~0x0fu) | ((byte)value & 0x0fu)); // Assignment to the right-half of the second byte
				}
			}

			public uint FlowLabel
			{
				get => (uint)(((_hdr[1] & ~0x0f) << 12) | ((_hdr[2]) << 8) | _hdr[3]);
				set
				{
					_hdr[1] = (byte)((value & 0x0f0000u) >> 16 | (_hdr[1] ^ 0xf0u));
					_hdr[2] = (byte)((value & 0x00ff00u) >> 8);
					_hdr[3] = (byte)((value & 0x0000ffu) >> 0);
				}
			}
		}
		#endregion

		#region Error Handling
			public static int _GetLastError()
		{
			return Marshal.GetLastWin32Error();
		}

		public static void GetLastError()
		{
			int err = _GetLastError();

			switch (err)
			{
				case 2:
					throw new FileNotFoundException("The driver files WinDivert32.sys or WinDivert64.sys were not found.");

				case 5:
					throw new AccessDeniedException("The calling application does not have Administrator privileges.");

				case 87:
					throw new ArgumentException("This indicates an invalid packet filter string, layer, priority, or flags.");

				case 122:
					throw new InsufficientBufferException("The captured packet is larger than the pPacket buffer.");

				case 232:
					throw new NoDataException("The handle has been shutdown using WinDivertShutdown() and the packet queue is empty.");

				case 577:
					throw new BadImageFormatException("The WinDivert32.sys or WinDivert64.sys driver does not have a valid digital signature (see the driver signing requirements).");

				case 654:
					throw new IncompatibleDriverException("An incompatible version of the WinDivert driver is currently loaded.");

				case 1058:
					throw new ServiceCannotStartException("The service cannot be started, either because it is disabled or because it has no enabled devices associated with it.");
				
				case 1060:
					throw new ServiceDoesNotExistException("The handle was opened with the WINDIVERT_FLAG_NO_INSTALL flag and the WinDivert driver is not already installed.");

				case 1232:
					throw new HostUnreachableException("This error occurs when an impostor packet (with pAddr->Impostor set to 1) is injected and the ip.TTL or ipv6.HopLimit field goes to zero. This is a defense of 'last resort' against infinite loops caused by impostor packets.");

				case 1275:
					throw new PlatformNotSupportedException("This error occurs for various reasons, including: the WinDivert driver is blocked by security software; or you are using a virtualization environment that does not support drivers.");

				case 1753:
					throw new ServiceNotRegisteredException("This error occurs when the Base Filtering Engine service has been disabled.");

				default:
					throw new Exception("Error " + err);
			}
		}
		#endregion

		#region Driver Status
		/// <summary>
		/// Check to see if the WinDivert service is running via the driver
		/// </summary>
		/// <returns>bool indicating driver is running or not</returns>
		public static bool DriverRunning()
		{
			IntPtr divert = WinDivert._WinDivertOpen("true", WinDivert.Layer.REFLECT, 0, WinDivert.Flag.SNIFF | WinDivert.Flag.RECV_ONLY | WinDivert.Flag.NO_INSTALL);
			if (divert.Equals(WinDivert.INVALID_HANDLE_VALUE))
			{
				try
				{
					WinDivert.GetLastError();
				}
				catch (ServiceDoesNotExistException)
				{
					return false;
				}
			}
			WinDivert._WinDivertClose(divert);
			return true;
		}

		/// <summary>
		/// Check to see if the WinDivert service is running via the Service Control Manager
		/// </summary>
		/// <returns>bool indicating driver is running or not</returns>
		public static bool ServiceRunning()
		{
			ServiceController[] scServices = ServiceController.GetDevices();
			foreach (ServiceController scService in scServices)
			{
				if (scService.ServiceName.Equals("WinDivert"))
				{
					return true;
				}
			}

			return false;
		}

		/// <summary>
		/// Returns true if the WinDivert driver is running; false if not
		/// </summary>
		/// <returns></returns>
		public static bool IsRunning()
		{
			return ServiceRunning();
		}

		/// <summary>
		/// Stop the WinDivert driver
		/// </summary>
		public static void StopDriver()
		{
			ServiceController[] scServices = ServiceController.GetDevices();
			foreach (ServiceController scService in scServices)
			{
				if (scService.ServiceName.Equals("WinDivert"))
				{
					scService.Stop();
				}
			}
		}
		#endregion
	}
}
