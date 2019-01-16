using System;

namespace WireguardPluginTask
{
    internal static class Constants
    {
        public const long RekeyAfterMessages = (1 << 64) - (1 << 16) - 1;
        public const long RejectAfterMessages = (1 << 64) - (1 << 4) - 1;
        public const int MaxTimerHandshakes = 90 / 5; /* RekeyAttemptTime / RekeyTimeout */
        public const int RekeyTimeoutJitterMaxMs = 334;
        public const int PaddingMultiple = 16;
        public static readonly TimeSpan RekeyAfterTime = TimeSpan.FromSeconds(120);
        public static readonly TimeSpan RekeyAttemptTime = TimeSpan.FromSeconds(90);
        public static readonly TimeSpan RekeyTimeout = TimeSpan.FromSeconds(5);
        public static readonly TimeSpan RejectAfterTime = TimeSpan.FromSeconds(180);
        public static readonly TimeSpan KeepaliveTimeout = TimeSpan.FromSeconds(10);
        public static readonly TimeSpan CookieRefreshTime = TimeSpan.FromSeconds(120);
        public static readonly TimeSpan HandshakeInitationRate = TimeSpan.FromSeconds(1.0 / 20);
    }
}