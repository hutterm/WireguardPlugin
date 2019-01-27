using System.Linq;
using System.Security.Cryptography;
using Elliptic;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace UnitTestProject1
{
    [TestClass]
    public class UnitTest1
    {
        [TestMethod]
        public void TestMethod1()
        {
            byte[] aliceRandomBytes = new byte[32];

            byte[] privateKeyBytes = new byte[]
            {
                40, 146, 87, 95, 87, 167, 114, 250, 89, 24, 160, 144, 158, 233, 161, 185,
                9, 153, 71, 88, 153, 107, 3, 49, 159, 174, 55, 184, 136, 80, 214, 123
            };

            //RNGCryptoServiceProvider.Create().GetBytes(aliceRandomBytes);
            //var clampPrivateKey = Curve25519.ClampPrivateKey(privateKeyBytes);
            //var publicKey = Curve25519.GetPublicKey(clampPrivateKey);
            //var result = Curve25519.GetSharedSecret(clampPrivateKey, publicKey);
            var priv = new byte[]
            {
                0x77, 0x07, 0x6d, 0x0a, 0x73, 0x18, 0xa5, 0x7d,
                0x3c, 0x16, 0xc1, 0x72, 0x51, 0xb2, 0x66, 0x45,
                0xdf, 0x4c, 0x2f, 0x87, 0xeb, 0xc0, 0x99, 0x2a,
                0xb1, 0x77, 0xfb, 0xa5, 0x1d, 0xb9, 0x2c, 0x2a
            };
            var pub = new byte[]
            {
                0xde, 0x9e, 0xdb, 0x7d, 0x7b, 0x7d, 0xc1, 0xb4,
                0xd3, 0x5b, 0x61, 0xc2, 0xec, 0xe4, 0x35, 0x37,
                0x3f, 0x83, 0x43, 0xc8, 0x5b, 0x78, 0x67, 0x4d,
                0xad, 0xfc, 0x7e, 0x14, 0x6f, 0x88, 0x2b, 0x4f
            };
            var res = new byte[]
            {
                0x4a, 0x5d, 0x9d, 0x5b, 0xa4, 0xce, 0x2d, 0xe1,
                0x72, 0x8e, 0x3b, 0xf4, 0x80, 0x35, 0x0f, 0x25,
                0xe0, 0x7e, 0x21, 0xc9, 0x47, 0xd1, 0x9e, 0x33,
                0x76, 0xf0, 0x9b, 0x3c, 0x1e, 0x16, 0x17, 0x42
            };

            var sharedSecret = Curve25519.GetSharedSecret(Curve25519.ClampPrivateKey(priv), pub);
            Assert.IsTrue(sharedSecret.SequenceEqual(res));
        }

        private static readonly byte[] input02 = new byte[] {0x9d};

        private static readonly byte[] output02 = new byte[]
        {
            0x94
        };

        private static readonly byte[] key02 = new byte[]
        {
            0x8c, 0x01, 0xac, 0xaf, 0x62, 0x63, 0x56, 0x7a,
            0xad, 0x23, 0x4c, 0x58, 0x29, 0x29, 0xbe, 0xab,
            0xe9, 0xf8, 0xdf, 0x6c, 0x8c, 0x74, 0x4d, 0x7d,
            0x13, 0x94, 0x10, 0x02, 0x3d, 0x8e, 0x9f, 0x94
        };

        private static readonly long nonce02 = 0x5d1b3bfdedd9f73a;

        [TestMethod]
        public void ChaCha()
        {
            var chaCha20Cipher = new ChaCha20Cipher.ChaCha20Cipher(key02, new byte[]
            {
                0x5d, 0x1b, 0x3b, 0xfd,
                0xed, 0xd9, 0xf7, 0x3a,
                0, 0, 0, 0
            }.Reverse().ToArray(), 0);
            var outBuffer = new byte[100];
            chaCha20Cipher.EncryptBytes(outBuffer,input02,input02.Length);

        }
    }
}
