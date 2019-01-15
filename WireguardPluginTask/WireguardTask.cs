using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Runtime.InteropServices;
using System.Runtime.InteropServices.WindowsRuntime;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Windows.ApplicationModel.Background;
using Windows.Devices.Bluetooth.Advertisement;
using Windows.Networking;
using Windows.Networking.Sockets;
using Windows.Networking.Vpn;
using Windows.Storage.Streams;
using BitManipulator;
using Noise;
using SauceControl.Blake2Fast;
namespace WireguardPluginTask
{
    /// <summary>
    /// how to debug this?
    /// https://stackoverflow.com/questions/43059456/how-to-debug-a-uwp-updatetask
    /// </summary>
    public sealed class WireguardTask : IBackgroundTask
    {
        private static IVpnPlugIn _pluginInstance = null;
        private static object _pluginLocker = new object();
        public static IVpnPlugIn GetPlugin()
        {
            if (_pluginInstance == null)
            {
                lock (_pluginLocker)
                {
                    if (_pluginInstance != null) return _pluginInstance;
                    _pluginInstance = new WireguardVpnPlugin();
                }
            }
            return _pluginInstance;
        }
        public void Run(IBackgroundTaskInstance taskInstance)
        {
            var backgroundTaskDeferral = taskInstance.GetDeferral();
            try
            {
                VpnChannel.ProcessEventAsync(GetPlugin(), taskInstance.TriggerDetails);
            }
            catch { }
            finally
            {
                backgroundTaskDeferral.Complete();
            }
        }
    }

    public enum ICMPv4Type : uint
    {
        EchoRequest = 8,
        EchoReply = 0
    }
    internal static class SpanExt
    {
        public static void Assign<T>(this Span<T> s, T v)
        {
            for (var i = 0; i < s.Length; i++) s[i] = v;
        }
    }
    public sealed class WireguardVpnPlugin : IVpnPlugIn
    {

        internal const uint VPN_MTU = 1500;
        internal const uint VPN_MAX_FRAME = 1512;

        public static void WireguardTest()
        {
            var ourPrivate = Convert.FromBase64String("WAmgVYXkbT2bCtdcDwolI88/iVi/aV3/PHcUBTQSYmo=");
            var ourPublic = Convert.FromBase64String("K5sF9yESrSBsOXPd6TcpKNgqoy1Ik3ZFKl4FolzrRyI=");
            var theirPublic = Convert.FromBase64String("qRCwZSKInrMAq5sepfCdaCsRJaoLe5jhtzfiw7CjbwM=");
            var preshared = Convert.FromBase64String("FpCyhws9cxwWoV4xELtfJvjJN+zQVRPISllRWgeopVE=");
            var protocol = new Protocol(
                HandshakePattern.IK,
                CipherFunction.ChaChaPoly,
                HashFunction.Blake2s,
                PatternModifiers.Psk2
            );
            var buffer = new byte[Protocol.MaxMessageLength];
            var buffer2 = new byte[Protocol.MaxMessageLength];
            int bufferRead = 0;
            using (var hs = protocol.Create(true,
                new ReadOnlySpan<byte>(Encoding.UTF8.GetBytes("WireGuard v1 zx2c4 Jason@zx2c4.com")),
                ourPrivate,
                theirPublic,
                new byte[][] { preshared }))
            {

                var now = DateTimeOffset.UtcNow; //replace with Noda.Time?
                var tai64n = new byte[12];
                (4611686018427387914ul + (ulong) now.ToUnixTimeSeconds()).ToBigEndian(tai64n);
                ((uint) (now.Millisecond * 1e6)).ToBigEndian(tai64n, 8);

                var initiationPacket = new List<byte> {1, 0, 0, 0};             //type initiation
                initiationPacket.AddRange(((uint)28).ToLittleEndian());         //sender, random 4byte

                var (bytesWritten, _, _) = hs.WriteMessage(tai64n, buffer);  
                initiationPacket.AddRange(buffer.Take(bytesWritten));           // should be 24byte, ephemeral, static, timestamp

                var hasher = Blake2s.CreateIncrementalHasher(32);
                hasher.Update(Encoding.UTF8.GetBytes("mac1----"));
                hasher.Update(theirPublic);
                hasher = Blake2s.CreateIncrementalHasher(16, hasher.Finish());
                hasher.Update(initiationPacket.ToArray());

                initiationPacket.AddRange(hasher.Finish().Take(16));            //mac1
                initiationPacket.AddRange(Enumerable.Repeat((byte)0,16));       //mac2 = zeros if no cookie last received


                var socket = new DatagramSocket();
                var responsePacket = new TaskCompletionSource<int>();
                var autoResetEvent = new AutoResetEvent(false);
                socket.MessageReceived += (sender, args) =>
                {
                    bufferRead = args.GetDataStream().AsStreamForRead().Read(buffer);
                    autoResetEvent.Set();
                };
                socket.ConnectAsync(new HostName("demo.wireguard.com"), "12913").AsTask().Wait();
                var streamWriter = new BinaryWriter(socket.OutputStream.AsStreamForWrite());
                streamWriter.Write(initiationPacket.ToArray());
                streamWriter.Flush();
                
                var successful = autoResetEvent.WaitOne(5000);
                if (!successful)
                    return;

                if (buffer[0] != 2)                                             //type init response
                    return;//"response packet type wrong: want %d, got %d"

                if (bufferRead != 92) //always this length! for type=2
                    return; //"response packet too short: want %d, got %d"

                if (buffer[1] != 0 || buffer[2] != 0 || buffer[3] != 0)
                    return; //"response packet has non-zero reserved fields"
                var theirIndex = buffer.LittleEndianToUInt32(4);
                var ourIndex= buffer.LittleEndianToUInt32(8);
                if( ourIndex != 28 )
                    return; //log.Fatalf("response packet index wrong: want %d, got %d", 28, ourIndex)
                var span = new Span<byte>(buffer);
                var (bytesRead, handshakeHash, transport) = hs.ReadMessage(span.Slice(12,48),
                    span.Slice(100)); //write on same buffer behind the received package (which 
                if (bytesRead != 0)
                    return; //"unexpected payload: %x"
                



                var icmpHeader = new IcmpHeader() {Type = 8, Id = 921, Sequence = 438};
                var pingMessage = icmpHeader.GetProtocolPacketBytes(Encoding.UTF8.GetBytes("WireGuard"));
                var pingHeader = new Ipv4Header()
                {
                    Version = 4,Length = 20,TotalLength = (ushort) (20+pingMessage.Length),
                    Protocol = 1,Ttl = 20,
                    SourceAddress = new IPAddress(new byte[]{10,189,129,2}),
                    DestinationAddress = new IPAddress(new byte[]{10,189,129,1})
                }.GetProtocolPacketBytes(new byte[0]);

                
                span[0] = 4;
                span.Slice(1,3).Assign((byte)0);
                theirIndex.ToLittleEndian(buffer, 4);
                0L.ToLittleEndian(buffer,8);                            //this is the counter, little endian u64
                bytesWritten = transport.WriteMessage(
                    pingHeader.Concat(pingMessage).Concat(Enumerable.Repeat((byte)0,11)).ToArray(), //pad message with 0 to make mod 16=0
                    span.Slice(16));

                //using (var streamWriter = new BinaryWriter(socket.OutputStream.AsStreamForWrite()))
                    streamWriter.Write(span.Slice(0,16+bytesWritten).ToArray());
                    streamWriter.Flush();
                successful = autoResetEvent.WaitOne(5000);
                if (!successful)
                    return;

                if (buffer[0] != 4)
                    return;//"response packet type wrong: want %d, got %d"
                if (buffer[1] != 0 || buffer[2] != 0 || buffer[3] != 0)
                    return; //"response packet has non-zero reserved fields"
                var replyPacket = buffer2.AsSpan(0,transport.ReadMessage(span.Slice(16,bufferRead-16),buffer2));
                if (replyPacket.Length != 48)
                    return;

                var replyHeaderLen = ((int) (replyPacket[0] & 0x0f)) << 2;
                var replyLen = buffer2.BigEndianToUInt16(2);
                var our_index_received = buffer.LittleEndianToUInt32(4);
                if (our_index_received != 28)
                    return;
                var nonce = buffer2.LittleEndianToUInt64(8);
                //if (nonce != 0)//not parsed correctly?
                //    return;
                var replyMessage = IcmpHeader.Create(buffer2.AsSpan(replyHeaderLen,replyLen-replyHeaderLen).ToArray(),ref bytesRead);
                if (replyMessage.Type != 0 || replyMessage.Code!=0)
                    return;
                if (replyMessage.Id != 921 || replyMessage.Sequence != 438)
                    return;
                var replyPayload = Encoding.UTF8.GetString(buffer2.AsSpan(replyLen - replyHeaderLen+bytesRead, replyHeaderLen - bytesRead));
                if (replyPayload != "WireGuard") //trim necessary?
                    return;
            }
        }


        public void Connect(VpnChannel channel)
        {
            try
            {
                
                //var vpnCustomPromptTextInput = new VpnCustomPromptTextInput() { DisplayName = "Give me some input" };
                ////this call is NOT asynchronous. awaiting the result will halt the program
                //channel.RequestCustomPromptAsync(new IVpnCustomPromptElement[]
                //{
                //    new VpnCustomPromptText() {DisplayName = "This is a test", Text = "Message"},
                //    vpnCustomPromptTextInput
                //});
                //var inputWas = vpnCustomPromptTextInput.Text;


                var transport = new DatagramSocket();
                transport.MessageReceived += Transport_MessageReceived;
                //var streamSocket = new StreamSocket();
                channel.AssociateTransport(transport, null);
                //channel.LogDiagnosticMessage("this is from the wireguard plugin");// supposedly under Event Viewer, under Application and Services Logs\Microsoft\Windows\Vpn Plugin Platform. but can't find


                transport.ConnectAsync(new HostName(channel.Configuration.ServerUris[0].Scheme),
                    channel.Configuration.ServerUris[0].LocalPath).AsTask().Wait();

                var vpnRouteAssignment = new VpnRouteAssignment();
                vpnRouteAssignment.Ipv4InclusionRoutes.Add(new VpnRoute(new HostName("10.0.0.0"), 8));
                vpnRouteAssignment.Ipv4InclusionRoutes.Add(new VpnRoute(new HostName("10.1.1.5"), 32));
                vpnRouteAssignment.Ipv4InclusionRoutes.Add(new VpnRoute(new HostName("10.1.1.0"), 24));

                var vpnDomainNameAssignment = new VpnDomainNameAssignment();
                vpnDomainNameAssignment.DomainNameList.Add(new VpnDomainNameInfo("wireguard.host",VpnDomainNameType.FullyQualified, null,null));
                vpnDomainNameAssignment.DomainNameList.Add(new VpnDomainNameInfo(".",VpnDomainNameType.Suffix, new []{new HostName("1.1.1.1"), },null));
                channel.StartExistingTransports( 
                    new[] { new HostName("10.1.1.1"), //this is our network interface address
                        new HostName("10.1.1.2"), }, 
                    null,
                    null,
                    vpnRouteAssignment,
                    vpnDomainNameAssignment,
                    VPN_MTU,
                    VPN_MAX_FRAME,
                    false
                );
            }
            catch (Exception e)
            {
                Console.WriteLine(e);
            }
        }

        private void Transport_MessageReceived(DatagramSocket sender, DatagramSocketMessageReceivedEventArgs args)
        {
        }

        public void Disconnect(VpnChannel channel)
        {
            channel.Stop();
        }
        public void GetKeepAlivePayload(VpnChannel channel, out VpnPacketBuffer keepAlivePacket)
        {
            keepAlivePacket = new VpnPacketBuffer(null, 0, 0);
        }
        public void Encapsulate(VpnChannel channel, VpnPacketBufferList packets, VpnPacketBufferList encapulatedPackets)
        {
            var vpnSendPacketBuffer = channel.GetVpnSendPacketBuffer();
            while(packets.Size>0) //can't iterate over packets
            {
                var packet = packets.RemoveAtEnd();
                var packetAppId = packet.AppId;
                var packetBuffer = packet.Buffer;
                var fromBuffer = DataReader.FromBuffer(packetBuffer);
                var fromBufferUnconsumedBufferLength = fromBuffer.UnconsumedBufferLength;
                var bytes = new byte[fromBufferUnconsumedBufferLength];
                fromBuffer.ReadBytes(bytes);

                var bytesRead = 0;
                var ipv4Header = Ipv4Header.Create(bytes, ref bytesRead);

                var vpnPacketBufferStatus = packet.Status;
                var packetTransportAffinity = packet.TransportAffinity;
                var packetTransportContext = packet.TransportContext;
                
                encapulatedPackets.Append(packet);

                //parse ip datagram and inspect destination IP
                //if destIP isn't found in peer list, drop and send ICMP "no route to host"?
            }
        }
        public void Decapsulate(VpnChannel channel, VpnPacketBuffer encapBuffer, VpnPacketBufferList decapsulatedPackets,
            VpnPacketBufferList controlPacketsToSend)
        {
            var buf = channel.GetVpnReceivePacketBuffer();
            // LogLine("Decapsulating one packet", channel);
            if (encapBuffer.Buffer.Length > buf.Buffer.Capacity)
            {
                //Drop larger packets.
                return;
            }
            encapBuffer.Buffer.CopyTo(buf.Buffer);
            buf.Buffer.Length = encapBuffer.Buffer.Length;
            decapsulatedPackets.Append(buf);
        }
    }
}
