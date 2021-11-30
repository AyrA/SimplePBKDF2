using System;
using System.Linq;
using System.Text;

namespace SimplePBKDF2
{
    class Program
    {
        static void Main(string[] args)
        {
            //Random salt value
            byte[] Salt = {
                0xA0, 0x09, 0xC1, 0xA4,
                0x85, 0x91, 0x2C, 0x6A,
                0xE6, 0x30, 0xD3, 0xE7,
                0x44, 0x24, 0x0B, 0x04
            };
            //Expected PBKDF2 output for SHA1, 1000 iterations, 16 bytes
            byte[] Expected = {
                0x17, 0xEB, 0x40, 0x14,
                0xC8, 0xC4, 0x61, 0xC3,
                0x00, 0xE9, 0xB6, 0x15,
                0x18, 0xB9, 0xA1, 0x8B
            };

            //These two keys yield the same result
            string K1 = "plnlrtfpijpuhqylxbgqiiyipieyxvfsavzgxbbcfusqkozwpngsyejqlmjsytrmd";
            string K2 = "eBkXQTfuBqp'cTcar&g*";

            var Result1 = PBKDF2.DeriveBytes("SHA1", Salt, Encoding.UTF8.GetBytes(K1), 1000, 16);
            var Result2 = PBKDF2.DeriveBytes("SHA1", Salt, Encoding.UTF8.GetBytes(K2), 1000, 16);

            if (!Result1.SequenceEqual(Result2))
            {
                Console.WriteLine("ERROR: Results do not match but should");
            }
            Console.WriteLine("Result: {0}", string.Concat(Result1.Select(m => m.ToString("X2"))));
            Console.WriteLine("Expect: {0}", string.Concat(Expected.Select(m => m.ToString("X2"))));
            if (!Result1.SequenceEqual(Expected))
            {
                Console.WriteLine("ERROR: Result does not match expected value");
            }

            Console.WriteLine("#END");
            Console.ReadKey(true);
        }
    }
}
