using System;
using System.Security.Cryptography;
using System.Text;

namespace SimplePBKDF2
{
    /// <summary>
    /// Provides an easy to understand PBKDF2 implementation.
    /// Note: This will create correct values, but it's very slow.
    /// In security critical applications you want to use <see cref="Rfc2898DeriveBytes"/> instead.
    /// </summary>
    public static class PBKDF2
    {
        /// <summary>
        /// Derives bytes using PBKDF2
        /// </summary>
        /// <param name="RngFunction">
        /// This is the name of the hash function. Usually SHA1
        /// but can be any other such as (but not exhaustively):
        /// SHA256, SHA512, RIPEMD160.
        /// Any algorithm that has a matching HMAC function will work.
        /// </param>
        /// <param name="Salt">
        /// Salt for the function.
        /// This should be randomly generated and be between 16 and 32 bytes.
        /// You need to store this somewhere if you want to create the same hash later.
        /// </param>
        /// <param name="Password">
        /// Key for the function.
        /// If your key is a string, use <see cref="Encoding.UTF8.GetBytes(string)"/>
        /// to convert it into a byte array.
        /// </param>
        /// <param name="Iterations">
        /// The number of iterations.
        /// Normally you want this to be 100'000 or more,
        /// but this implementation is not made to be fast, but easy to understand.
        /// Keep it around 1'000 - 10'000 for this demo.
        /// </param>
        /// <param name="ByteCount">
        /// The number of bytes you want to get out of this function
        /// </param>
        /// <returns>
        /// Randomly looking but deterministic bytes
        /// </returns>
        public static byte[] DeriveBytes(string RngFunction, byte[] Salt, byte[] Password, int Iterations, int ByteCount)
        {
            #region Validation
            //Make sure something was specified
            if (string.IsNullOrEmpty(RngFunction))
            {
                throw new ArgumentException($"'{nameof(RngFunction)}' cannot be null or empty.", nameof(RngFunction));
            }
            //Cannot use null as salt
            if (Salt is null)
            {
                throw new ArgumentNullException(nameof(Salt));
            }
            //Cannot use null as password either
            if (Password is null)
            {
                throw new ArgumentNullException(nameof(Password));
            }
            //Require at least one iteration
            if (Iterations < 1)
            {
                throw new ArgumentOutOfRangeException(nameof(Iterations));
            }
            //Require at least one output byte
            if (ByteCount < 1)
            {
                throw new ArgumentOutOfRangeException(nameof(ByteCount));
            }
            #endregion

            //Create the HMAC of the supplied algorithm
            var KeyHash = HMAC.Create("HMAC" + RngFunction);

            //Size of the algorithm in bytes.
            //Note that sizes in cryptographic algorithms are often reported in bits, not bytes,
            //hence why we divide the value by 8
            var Size = KeyHash.HashSize / 8;

            //Shorten the key if it's longer than the hash size.
            //No action is performed if the key is shorter
            if (Password.Length > Size)
            {
                //Shortening is done by regular hashing, not using the HMAC
                using (var Hasher = HashAlgorithm.Create(RngFunction))
                {
                    Password = Hasher.ComputeHash(Password);
                }
            }
            using (KeyHash)
            {
                //Number of hash blocks we need to fit the requested byte count
                var BlockCount = ByteCount / Size;
                //If there is a remainder, we need to add one extra block
                //For example with SHA1 (block size 20 bytes) and 30 bytes of data:
                //30/20=1 (integer division always rounds down)
                //30%20=10 (remainder is not zero, so increase block size by one)
                //Final size: 2 blocks
                //If you prefer this in one line:
                //BlockCount = ByteCount / Size + (ByteCount % Size == 0 ? 0 : 1);
                if (ByteCount % Size != 0)
                {
                    ++BlockCount;
                }
                //This holds the final output data
                byte[] Output = new byte[ByteCount];
                //Set key
                KeyHash.Key = Password;
                //Hash as many blocks as needed
                for (var BlockIndex = 1; BlockIndex <= BlockCount; BlockIndex++)
                {
                    //Hash a block of data
                    var Round = HashBlock(KeyHash, Salt, BlockIndex, Iterations);
                    //The location of where the data goes in the output
                    //This basically starts each output at the end of the previous one
                    var BlockOffset = (BlockIndex - 1) * Size;
                    //Normally we copy all bytes but the last chunk may be smaller
                    var BytesToCopy = Math.Min(Round.Length, ByteCount - BlockOffset);
                    Array.Copy(Round, 0, Output, BlockOffset, BytesToCopy);
                }
                return Output;
            }
        }

        /// <summary>
        /// Hashes a block of output data
        /// </summary>
        /// <param name="Hasher">Hash algorithm</param>
        /// <param name="Salt">Salt value</param>
        /// <param name="BlockIndex">Block index (starts at 1, not 0)</param>
        /// <param name="IterationCount">Number of iterations</param>
        /// <returns>Hashed block data</returns>
        private static byte[] HashBlock(KeyedHashAlgorithm Hasher, byte[] Salt, int BlockIndex, int IterationCount)
        {
            //First round is special by additionally using the block index in the input
            byte[] Data = Hasher.ComputeHash(GetFirstBlockData(Salt, BlockIndex));
            //Holds the final result
            byte[] Result = (byte[])Data.Clone();
            //rounds 2 to IterationCount use the result "Data" of the previous run
            for (var i = 2; i <= IterationCount; i++)
            {
                byte[] Temp = Hasher.ComputeHash(Data);
                //The result is XOR combined with the input data
                for (var j = 0; j < Temp.Length; j++)
                {
                    Result[j] ^= Temp[j];
                }
                //Use the last result as the data for the next iteration
                Data = Temp;
            }
            return Result;
        }

        /// <summary>
        /// Gets the value used for the first block hash
        /// </summary>
        /// <param name="Salt">Salt</param>
        /// <param name="BlockIndex">Block index (starts at 1, not 0)</param>
        /// <returns>value for first iteration of the hasher</returns>
        private static byte[] GetFirstBlockData(byte[] Salt, int BlockIndex)
        {
            var Data = new byte[Salt.Length + 4];
            //Copy key into the buffer
            Array.Copy(Salt, Data, Salt.Length);
            //Append the BlockIndex as 32 bit big endian integer
            Data[Salt.Length] = (byte)(BlockIndex >> 24);
            Data[Salt.Length + 1] = (byte)(BlockIndex >> 16 & 0xFF);
            Data[Salt.Length + 2] = (byte)(BlockIndex >> 8 & 0xFF);
            Data[Salt.Length + 3] = (byte)(BlockIndex & 0xFF);
            return Data;
        }
    }
}
