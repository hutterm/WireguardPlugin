using System;
using WireguardPluginTask.cipher;

namespace WireguardPluginTask
{
    internal struct Keypair
    {
        UInt64 sendNonce;
        AEAD send;
        AEAD receive;
        replay.ReplayFilter replayFilter;
        bool isInitiator;
        time.Time created;
        UInt32 localIndex;

        UInt32 remoteIndex;
    }


    internal class uint64 : UInt16 { }

    class error : Exception { }
}

namespace WireguardPluginTask.cipher
{
    interface AEAD
    {
        // NonceSize returns the size of the nonce that must be passed to Seal
        // and Open.
        int NonceSize();

        // Overhead returns the maximum difference between the lengths of a
        // plaintext and its ciphertext.
        int Overhead();

        // Seal encrypts and authenticates plaintext, authenticates the
        // additional data and appends the result to dst, returning the updated
        // slice. The nonce must be NonceSize() bytes long and unique for all
        // time, for a given key.
        //
        // To reuse plaintext's storage for the encrypted output, use plaintext[:0]
        // as dst. Otherwise, the remaining capacity of dst must not overlap plaintext.
        byte[] Seal(byte[] dst, byte[] nonce, byte[] plaintext, byte[] additionalData);

        // Open decrypts and authenticates ciphertext, authenticates the
        // additional data and, if successful, appends the resulting plaintext
        // to dst, returning the updated slice. The nonce must be NonceSize()
        // bytes long and both it and the additional data must match the
        // value passed to Seal.
        //
        // To reuse ciphertext's storage for the decrypted output, use ciphertext[:0]
        // as dst. Otherwise, the remaining capacity of dst must not overlap plaintext.
        //
        // Even if the function fails, the contents of dst, up to its capacity,
        // may be overwritten.
        (byte[], error) Open(byte[] dst, byte[] nonce, byte[] ciphertext, byte[] additionalData);
    }
}


namespace WireguardPluginTask.time
{
    internal class Time : DateTime { }
}