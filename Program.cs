using System;
using System.Security.Cryptography;
using System.Text;

namespace coding_project
{

    class Program
    {
        static void Main(string[] args)
        {
            try
            {
                Console.WriteLine("Select encryption (write 1) or decryption (write 2).");
                string enc_or_dec = Console.ReadLine();
                while(enc_or_dec != "1" && enc_or_dec != "2")
                {
                    Console.WriteLine("Select encryption (write 1) or decryption (write 2).");
                    enc_or_dec = Console.ReadLine();
                }

                byte[] desIV = {};

                if (enc_or_dec == "1")
                {
                    Console.WriteLine("Write the word/text you want to encrypt.");
                }
                else
                {
                    Console.WriteLine("Write the word/text you want to decrypt.");

                }


                string original = Console.ReadLine();
                while (original == null)
                {
                    Console.WriteLine("Write a word/text.");
                    original = Console.ReadLine();
                }
                Console.WriteLine("Write a secret key");
                string key = Console.ReadLine(); // Replace with your secret key
                while (key == null)
                {
                    Console.WriteLine("Write a valid password.");
                    key = Console.ReadLine();
                }
                byte[] desKey = GenerateKey(key);


                if(enc_or_dec == "1")
                {
                    desIV = GenerateIV();
                    Console.WriteLine("We will give you an Initial Vector, please keep it to decrypt the encrypt text");
                    string ivString = BitConverter.ToString(desIV).Replace("-", ""); // Convert IV bytes to a hexadecimal string
                    Console.WriteLine("Initial Vector: " + ivString);
                    Console.WriteLine("Original: " + original);
                    byte[] encrypted = EncryptStringToBytes(original, desKey, desIV); // Pass the IV
                    Console.WriteLine("Encrypted: " + Convert.ToBase64String(encrypted));
                }
                else
                {
                    Console.WriteLine("Write the Initial Vector for decryption");
                    string ivInput = Console.ReadLine();
                    byte[] decryptedIV = new byte[ivInput.Length / 2]; // Convert hexadecimal string to byte array
                    for (int i = 0; i < decryptedIV.Length; i++)
                    {
                        decryptedIV[i] = Convert.ToByte(ivInput.Substring(i * 2, 2), 16);
                    }

                    byte[] encrypted = Convert.FromBase64String(original); // Convert the Base64 encoded string to bytes
                    string decrypted = DecryptStringFromBytes(encrypted, desKey, decryptedIV); // Pass the IV bytes for decryption
                    Console.WriteLine("Decrypted: " + decrypted);
                }
                

                
            }
            catch (Exception e)
            {
                Console.WriteLine("Error: " + e.Message);
            }

            Console.ReadLine();
        }

        static byte[] EncryptStringToBytes(string plainText, byte[] key, byte[] iv)
        {
            byte[] plainBytes = Encoding.UTF8.GetBytes(plainText);

            DES des = DES.Create();
            try
            {
                des.Key = key;
                des.IV = iv; // Set the IV

                des.Padding = PaddingMode.PKCS7;

                ICryptoTransform encryptor = des.CreateEncryptor(des.Key, des.IV);

                using (MemoryStream msEncrypt = new MemoryStream())
                {
                    using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                    {
                        csEncrypt.Write(plainBytes, 0, plainBytes.Length);
                        csEncrypt.FlushFinalBlock();
                        return msEncrypt.ToArray();
                    }
                }
            }
            finally
            {
                des.Dispose();
            }
        }

        static string DecryptStringFromBytes(byte[] cipherText, byte[] key, byte[] iv)
        {
            DES des = DES.Create();
            try
            {
                des.Key = key;
                des.IV = iv; // Set the IV for decryption

                des.Padding = PaddingMode.PKCS7;

                ICryptoTransform decryptor = des.CreateDecryptor(des.Key, des.IV);

                using (MemoryStream msDecrypt = new MemoryStream(cipherText))
                {
                    using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                    {
                        using (StreamReader srDecrypt = new StreamReader(csDecrypt))
                        {
                            return srDecrypt.ReadToEnd();
                        }
                    }
                }
            }
            finally
            {
                des.Dispose();
            }
        }

        static byte[] GenerateKey(string key)
        {
            // Create an instance of the MD5 hashing algorithm
            using (MD5 md5 = MD5.Create())
            {
                // Convert the input string key into bytes using UTF-8 encoding
                byte[] inputBytes = Encoding.UTF8.GetBytes(key);

                // Compute the MD5 hash of the input bytes
                byte[] hashBytes = md5.ComputeHash(inputBytes);

                // Take the first 8 bytes from the MD5 hash as the DES key
                byte[] desKey = new byte[8];
                Array.Copy(hashBytes, 0, desKey, 0, 8);

                // Return the generated DES key
                return desKey;
            }
        }

        static byte[] GenerateIV()
        {
            // DES IV is also 64 bits (8 bytes)
            byte[] iv = new byte[8];
            using (RandomNumberGenerator rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(iv);
            }
            return iv;
        }

    }
}
