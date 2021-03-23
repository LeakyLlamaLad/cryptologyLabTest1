using System;
using System.Text;
using System.IO;
using System.Text.RegularExpressions;
using System.Security.Cryptography;

namespace EncryptionWithSalt
{
    class EncryptionWithSalt
    {
        const string PLAINTEXT = @"..\..\..\PlainText.txt";
        const string CIPHERTEXT = @"..\..\..\..\DecryptionWithSalt\CipherText.txt";
        static void Main(string[] args)
        {
            EncryptFileWithSalt(PLAINTEXT, CIPHERTEXT, "password");
        }
        private static void EncryptFileWithSalt(string plainText, string cipherText, string password)
        {
            RijndaelManaged rijndaelCipher = new RijndaelManaged();

            FileStream fin = new FileStream(plainText, FileMode.Open, FileAccess.Read);
            FileStream fout = new FileStream(cipherText, FileMode.Create, FileAccess.Write);

            byte[] salt = System.Text.Encoding.UTF8.GetBytes("SaltHere");// must be at least 8 bytes

            Rfc2898DeriveBytes pwdGen = new Rfc2898DeriveBytes(password, salt);

            ICryptoTransform enCryptor = rijndaelCipher.CreateEncryptor(
                pwdGen.GetBytes(32), pwdGen.GetBytes(16));

            CryptoStream encStream = new CryptoStream(
                fout, enCryptor, CryptoStreamMode.Write);

            int ByteData;
            while ((ByteData = fin.ReadByte()) != -1)
            {
                encStream.WriteByte((byte)ByteData);
            }

            encStream.Close(); fin.Close(); fout.Close();
        }
    }
}
