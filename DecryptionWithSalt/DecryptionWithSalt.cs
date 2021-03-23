using System;
using System.Text;
using System.IO;
using System.Text.RegularExpressions;
using System.Security.Cryptography;

namespace DecryptionWithSalt
{
    class DecryptionWithSalt
    {
        const string CIPHERTEXT = @"..\..\..\CipherText.txt";
        const string PLAINTEXT = @"..\..\..\RecoveredSaltedMessage.txt";
        static void Main(string[] args)
        {
            DecryptFileWithSalt(CIPHERTEXT, PLAINTEXT, "password");
        }
        private static void DecryptFileWithSalt(string cipherText, string plainText, string password)
        {
            RijndaelManaged RijndaelCipher = new RijndaelManaged();

            FileStream fin = new FileStream(cipherText, FileMode.Open, FileAccess.Read);
            FileStream fout = new FileStream(plainText, FileMode.Create, FileAccess.Write);

            byte[] salt = System.Text.Encoding.UTF8.GetBytes("SaltHere");

            Rfc2898DeriveBytes pwdGen = new Rfc2898DeriveBytes(password, salt);

            ICryptoTransform deCryptor = RijndaelCipher.CreateDecryptor(pwdGen.GetBytes(32), pwdGen.GetBytes(16));

            CryptoStream decStream = new CryptoStream(fout, deCryptor, CryptoStreamMode.Write);

            int ByteData;
            while ((ByteData = fin.ReadByte()) != -1)
            {
                decStream.WriteByte((byte)ByteData);
            }
            decStream.Close(); fin.Close(); fout.Close();
        }
    }
}
