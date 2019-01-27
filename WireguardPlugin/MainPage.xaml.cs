using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices.WindowsRuntime;
using Windows.Foundation;
using Windows.Foundation.Collections;
using Windows.UI.Xaml;
using Windows.UI.Xaml.Controls;
using Windows.UI.Xaml.Controls.Primitives;
using Windows.UI.Xaml.Data;
using Windows.UI.Xaml.Input;
using Windows.UI.Xaml.Media;
using Windows.UI.Xaml.Navigation;
using Merkator.Crypto;

//using org.whispersystems.curve25519;

// The Blank Page item template is documented at https://go.microsoft.com/fwlink/?LinkId=402352&clcid=0x409
namespace WireguardPlugin
{
    /// <summary>
    /// An empty page that can be used on its own or navigated to within a Frame.
    /// </summary>
    public sealed partial class MainPage : Page
    {
        public MainPage()
        {
            this.InitializeComponent();
            ////WireguardPluginTask.WireguardVpnPlugin.WireguardTest();
            //var curve25519 = Curve25519.getInstance(Curve25519.CSHARP);
            //var secret = new byte[32];
            //secret[0] = 1;
            byte[] privateKeyBytes = new byte[] {
                40, 146, 87, 95, 87, 167, 114, 250, 89, 24, 160, 144, 158, 233, 161, 185,
                9, 153, 71, 88, 153, 107, 3, 49, 159, 174, 55, 184, 136, 80, 214, 123
            };

            //byte[] expectedPublicKey = new byte[] {
            //    5, 4, 110, 87, 229, 103, 40, 213, 31, 232, 220, 105, 168, 107, 115, 255,
            //    147, 215, 171, 130, 192, 180, 71, 12, 6, 20, 212, 30, 157, 31, 175, 20
            //};

            //var generatePublicKey = curve25519.generatePublicKey(privateKeyBytes);
            

        }
    }
}
