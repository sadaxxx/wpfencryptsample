using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Navigation;
using System.Windows.Shapes;
using Path = System.IO.Path;

namespace WpfApp1
{
    /// <summary>
    /// MainWindow.xaml の相互作用ロジック
    /// </summary>
    public partial class MainWindow : Window
    {
        public MainWindow()
        {
            InitializeComponent();
        }

        [DllImport("rijn.dll")]
        private static extern int EncryptFile(string SourceFileName, string DestFileName, string key);  //暗号化
        [DllImport("rijn.dll")]
        private static extern int DecryptFile(string SourceFileName, string DestFileName, string key);  //復号化
        private string directryStr = "C:\\Users\\sada3\\Desktop\\dll\\WpfApp1\\bin\\Debug\\";
        // DLL
        private void BComp_Click_1(object sender, RoutedEventArgs e)
        {
            Console.WriteLine($"DLL暗号化");
            // 暗号化ファイルがある場合は削除。
            deleteenc();
            // 圧縮
            compress();
            // 暗号化
            dllenc();
            // テンポラリ削除
            deletetmp();
        }
        private void dllenc()
        {
            var sw = new System.Diagnostics.Stopwatch();
            sw.Start();
            // 暗号化先がある場合は先に削除
            File.Delete($"{directryStr}enc");
            _ = EncryptFile($"{directryStr}tmpenc", $"{directryStr}enc", "abc123");
            sw.Stop();
            TimeSpan ts = sw.Elapsed;
            Console.WriteLine($"　　暗号化　{ts}");

        }
        // DLL
        private void BDecomp_Click_1(object sender, RoutedEventArgs e)
        {
            Console.WriteLine($"DLL複合化");
            // 複合化
            dlldec();
            // 解凍
            decompress();
            // テンポラリ削除
            deletetmp();
        }
        private void dlldec()
        {
            var sw = new System.Diagnostics.Stopwatch();
            sw.Start();
            _ = DecryptFile($"{directryStr}enc", $"{directryStr}tmpenc", "abc123");
            sw.Stop();
            TimeSpan ts = sw.Elapsed;
            Console.WriteLine($"　　複合化　{ts}");
        }
        // .net
        private void dotnetBComp_Click(object sender, RoutedEventArgs e)
        {
            Console.WriteLine($"net暗号化");
            // 暗号化ファイルがある場合は削除。
            deleteenc();
            // 圧縮
            compress();
            // 暗号化
            dotnetenc();
            // テンポラリ削除
            deletetmp();
        }
        static int BlockSize = 128;              // BlockSize = 16bytes
        static int KeySize = 256;                // KeySize = 16bytes
        private void dotnetenc()
        {
            var sw = new System.Diagnostics.Stopwatch();
            sw.Start();
            // 暗号化先がある場合は先に削除
            File.Delete($"{directryStr}enc");
            string FilePath = $"{directryStr}tmpenc";
            string OutFilePath = $"{directryStr}enc";
            using (FileStream outfs = new FileStream(OutFilePath, FileMode.Create, FileAccess.Write))
            {
                using (RijndaelManaged rij = new RijndaelManaged())
                {
                    rij.BlockSize = BlockSize;
                    rij.KeySize = KeySize;
                    rij.Mode = CipherMode.CBC;        // CBC mode
                    rij.Padding = PaddingMode.PKCS7;    // Padding mode is "PKCS7".

                    //入力されたパスワードをベースに擬似乱数を新たに生成
                    Rfc2898DeriveBytes deriveBytes = new Rfc2898DeriveBytes("abc123", 16);
                    byte[] salt = new byte[16]; // Rfc2898DeriveBytesが内部生成したなソルトを取得
                    salt = deriveBytes.Salt;
                    // 生成した擬似乱数から16バイト切り出したデータをパスワードにする
                    byte[] bufferKey = deriveBytes.GetBytes(16);

                    rij.Key = bufferKey;
                    // IV ( Initilization Vector ) は、Managedにつくらせる
                    rij.GenerateIV();
                    //Encryption interface.
                    ICryptoTransform encryptor = rij.CreateEncryptor(rij.Key, rij.IV);

                    using (CryptoStream cse = new CryptoStream(outfs, encryptor, CryptoStreamMode.Write))
                    {
                        outfs.Write(salt, 0, 16);     // salt をファイル先頭に埋め込む
                        outfs.Write(rij.IV, 0, 16); // 次にIVもファイルに埋め込む
                        using (DeflateStream ds = new DeflateStream(cse, CompressionMode.Compress)) //圧縮
                        {
                            using (FileStream fs = new FileStream(FilePath, FileMode.Open, FileAccess.Read))
                            {
                                int len;
                                byte[] buffer = new byte[4096];
                                while ((len = fs.Read(buffer, 0, 4096)) > 0)
                                {
                                    ds.Write(buffer, 0, len);
                                }
                            }
                        }
                    }
                }
            }
            sw.Stop();
            TimeSpan ts = sw.Elapsed;
            Console.WriteLine($"　　暗号化　{ts}");
        }

        // .net
        private void dotnetBDecomp_Click(object sender, RoutedEventArgs e)
        {
            Console.WriteLine($"net複合化");
            // 複合化
            dotnetdec();
            // 解凍
            decompress();
        }
        private void dotnetdec()
        {
            var sw = new System.Diagnostics.Stopwatch();
            sw.Start();
            var FilePath = $"{directryStr}enc";
            string OutFilePath = $"{directryStr}tmpenc";
            using (FileStream outfs = new FileStream(OutFilePath, FileMode.Create, FileAccess.Write))
            {
                using (FileStream fs = new FileStream(FilePath, FileMode.Open, FileAccess.Read))
                {
                    using (RijndaelManaged rij = new RijndaelManaged())
                    {
                        rij.BlockSize = BlockSize;
                        rij.KeySize = KeySize;
                        rij.Mode = CipherMode.CBC;        // CBC mode
                        rij.Padding = PaddingMode.PKCS7;    // Padding mode is "PKCS7".

                        // salt
                        byte[] salt = new byte[16];
                        fs.Read(salt, 0, 16);

                        // Initilization Vector
                        byte[] iv = new byte[16];
                        fs.Read(iv, 0, 16);
                        rij.IV = iv;

                        // ivをsaltにしてパスワードを擬似乱数に変換
                        Rfc2898DeriveBytes deriveBytes = new Rfc2898DeriveBytes("abc123", salt);
                        byte[] bufferKey = deriveBytes.GetBytes(16);    // 16バイトのsaltを切り出してパスワードに変換
                        rij.Key = bufferKey;

                        //Decryption interface.
                        ICryptoTransform decryptor = rij.CreateDecryptor(rij.Key, rij.IV);

                        using (CryptoStream cse = new CryptoStream(fs, decryptor, CryptoStreamMode.Read))
                        {
                            using (DeflateStream ds = new DeflateStream(cse, CompressionMode.Decompress))   //解凍
                            {
                                int len;
                                byte[] buffer = new byte[4096];
                                while ((len = ds.Read(buffer, 0, 4096)) > 0)
                                {
                                    outfs.Write(buffer, 0, len);
                                }
                            }
                        }
                    }
                }
            }
            sw.Stop();
            TimeSpan ts = sw.Elapsed;
            Console.WriteLine($"　　複合化　{ts}");

        }
        private void Button_Click_1(object sender, RoutedEventArgs e)
        {
            Console.WriteLine($"dll暗号化複合化");
            for (var i = 1; i <= 50; i++)
            {
                var sw = new System.Diagnostics.Stopwatch();
                sw.Start();
                Console.WriteLine($"　dll暗号化複合化:" + i);
                // 圧縮
                compress();
                // 暗号化
                dllenc();
                // テンポラリ削除
                deletetmp();
                // 複合化
                dlldec();
                // 解凍
                decompress();
                sw.Stop();
                TimeSpan ts = sw.Elapsed;
                Console.WriteLine($"　dll暗号化複合化　{ts}");
            }
        }

        private void Button_Click(object sender, RoutedEventArgs e)
        {
            Console.WriteLine($"dotnet暗号化複合化");
            for (var i = 1; i <= 50; i++)
            {
                var sw = new System.Diagnostics.Stopwatch();
                sw.Start();
                Console.WriteLine($"　dotnet暗号化複合化:" + i);
                // 圧縮
                compress();
                // 暗号化
                dotnetenc();
                // テンポラリ削除
                deletetmp();
                // 複合化
                dotnetdec();
                // 解凍
                decompress();
                sw.Stop();
                TimeSpan ts = sw.Elapsed;
                Console.WriteLine($"　dotnet暗号化複合化　{ts}");

            }

        }

        private void compress()
        {
            var sw = new System.Diagnostics.Stopwatch();
            // 圧縮
            sw.Start();
            // 圧縮先がある場合は先に削除
            File.Delete($"{directryStr}tmpenc");
            ZipFile.CreateFromDirectory($"{directryStr}encdir", $"{directryStr}tmpenc");
            sw.Stop();
            TimeSpan ts = sw.Elapsed;
            Console.WriteLine($"　　圧縮　{ts}");
        }
        private void decompress()
        {
            var sw = new System.Diagnostics.Stopwatch();
            // 解凍
            sw.Start();
            ZipFile.ExtractToDirectory($"{directryStr}tmpenc", $"{directryStr}decdir");
            sw.Stop();
            TimeSpan ts = sw.Elapsed;
            Console.WriteLine($"　　解凍　{ts}");
        }
        private void deletetmp()
        {
            var sw = new System.Diagnostics.Stopwatch();
            // テンポラリ削除
            sw.Start();
            File.Delete($"{directryStr}tmpenc");
            DirectoryInfo d = new System.IO.DirectoryInfo($"{directryStr}\\decdir");
            if (d.Exists)
            {
                d.Delete(true);
            }
            sw.Stop();
            TimeSpan ts = sw.Elapsed;
            Console.WriteLine($"　　テンポラリ削除　{ts}");

        }
        private void deleteenc()
        {
            var sw = new System.Diagnostics.Stopwatch();
            // 暗号化ファイル削除
            sw.Start();
            File.Delete($"{directryStr}enc");
            sw.Stop();
            TimeSpan ts = sw.Elapsed;
            Console.WriteLine($"　　暗号化ファイル削除　{ts}");

        }
    }
}
