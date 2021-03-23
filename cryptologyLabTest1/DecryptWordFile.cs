using System;
using System.Text;
using System.IO;
using System.Text.RegularExpressions;
using System.Security.Cryptography;

namespace DecryptWordFile
{
    class DecryptWordFile
    {
        const string CIPHERTEXT = @"..\..\..\..\CipherText.txt";
        const string RECOVEREDTEXT = @"..\..\..\..\RecoverMessage.docx";        
        static void Main(string[] args)
        {
            DecryptDocx(CIPHERTEXT, RECOVEREDTEXT);            
        }
        private static void DecryptDocx(String cipherText, String recoveredText)
        {
            SymmetricAlgorithm tdes = TripleDES.Create();

            FileStream fin = new FileStream(cipherText, FileMode.Open, FileAccess.Read);
            FileStream fout = new FileStream(recoveredText, FileMode.OpenOrCreate, FileAccess.Write);
            FileStream fsKeyInfo = new FileStream(@"..\..\..\..\keyInfo2.txt", FileMode.Open, FileAccess.Read);
            FileStream fsIVInfo = new FileStream(@"..\..\..\..\ivInfo2.txt", FileMode.Open, FileAccess.Read);

            //set key (key must by byte[])
            byte[] bytes64 = new byte[tdes.Key.Length];
            fsKeyInfo.Read(bytes64, 0, tdes.Key.Length);
            tdes.Key = bytes64;

            //set iv (key must by byte[])
            bytes64 = new byte[tdes.IV.Length];
            fsIVInfo.Read(bytes64, 0, tdes.IV.Length);
            tdes.IV = bytes64;

            byte[] bin = new byte[100];
            long rdlen = 0;
            long totlen = fin.Length;
            int len;

            CryptoStream decStream = new CryptoStream(
                fout, tdes.CreateDecryptor(tdes.Key, tdes.IV), CryptoStreamMode.Write);

            Console.WriteLine("Decrypting...");

            while (rdlen < totlen)
            {
                len = fin.Read(bin, 0, 100);
                decStream.Write(bin, 0, len);
                rdlen = rdlen + len;
            }
            decStream.Clear(); decStream.Close(); fin.Close(); fout.Close();
        }
    }
}
