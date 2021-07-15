/*
    Copyright(c) 2021 Gluwa, Inc.

    This file is part of Creditcoin.

    Creditcoin is free software: you can redistribute it and/or modify
    it under the terms of the GNU Lesser General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.
    
    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
    GNU Lesser General Public License for more details.
    
    You should have received a copy of the GNU Lesser General Public License
    along with Creditcoin. If not, see <https://www.gnu.org/licenses/>.
*/

using System;
using Sawtooth.Sdk.Client;

namespace ccplugin
{
    /// <summary>
    ///  Temporary workaround for Sawtooth .NET signing bug.
    /// </summary>
    class SafeSignerWrapper: ISigner
    {
        private const int SIG_SIZE = 64;

        private readonly Signer innerSigner;

        public SafeSignerWrapper(Signer signer)
        {
            innerSigner = signer;
        }

        /// <inheritdoc/>
        public byte[] GetPublicKey()
        {
            return innerSigner.GetPublicKey();
        }

        /// <inheritdoc/>
        /// <remarks>
        ///  If the size is less than 256 bits, this left pads zeros to the
        ///  R and S signature pair, starting with S.
        /// </remarks>
        public byte[] Sign(byte[] digest)
        {
            var signatureBytes = innerSigner.Sign(digest);

            if (signatureBytes.Length < SIG_SIZE)
            {
                var lengthDiff = SIG_SIZE - signatureBytes.Length;
                // Left pad second half to 32 bytes.
                Array.Resize(ref signatureBytes, SIG_SIZE);
                Array.Copy(signatureBytes, SIG_SIZE / 2,
                    signatureBytes, SIG_SIZE / 2 + lengthDiff, SIG_SIZE / 2 - lengthDiff);
                Array.Clear(signatureBytes, SIG_SIZE / 2, lengthDiff);
                // Shift the rightmost byte of first half to second until the signature is valid.
                var publicKey = GetPublicKey();
                for (var i = 1; i <= lengthDiff + 1; i++)
                {
                    if (Signer.Verify(digest, signatureBytes, publicKey))
                    {
                        break;
                    }
                    else if (i > lengthDiff) // If all combinations are invalid.
                    {
                        // Extract the original signature.
                        var signatureBase64 = System.Convert.ToBase64String(signatureBytes, lengthDiff,
                            signatureBytes.Length - lengthDiff);
                        throw new InvalidOperationException("Unable to create valid signature: " + signatureBase64);
                    }
                    else
                    {
                        signatureBytes[SIG_SIZE / 2 + lengthDiff - i] = signatureBytes[SIG_SIZE / 2 - 1];
                        Array.Copy(signatureBytes, 0, signatureBytes, 1, SIG_SIZE / 2 - 1);
                        signatureBytes[0] = (byte)0;
                    }
                }
            }

            return signatureBytes;
        }
    }
}