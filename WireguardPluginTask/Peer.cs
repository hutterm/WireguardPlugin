using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace WireguardPluginTask
{
    internal class Peer
    {
        private bool isRunning;

        private object RWMutex;                // Mostly protects endpoint, but is generally taken whenever we modify peer
            keypairs                    Keypairs
            handshake                   Handshake

            device* Device

            endpoint Endpoint

            persistentKeepaliveInterval uint16
    }
}
