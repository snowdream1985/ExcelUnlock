using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Text.Json;
using NPOI.XSSF.UserModel;
using NPOI.POIFS.FileSystem;
using NPOI.SS.UserModel;
using NPOI.POIFS.Crypt;
using NPOI.Util;
using Org.BouncyCastle.Crypto;
using DocumentFormat.OpenXml.Packaging;

class Program
{
    private enum CrackMode
    {
        SinglePassword,
        Dictionary,
        BruteForce,
        Mask
    }

    private static class CharacterSets
    {
        public const string Digits = "0123456789";
        public const string LowerCase = "abcdefghijklmnopqrstuvwxyz";
        public const string UpperCase = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
        public const string Special = "!@#$%^&*()_+-=[]{}|;:,.<>?";
        public const string CustomCharSet = "CustomCharSet.txt";
    }

    private class CrackState
    {
        public string FilePath { get; set; } = "";
        public CrackMode Mode { get; set; }
        public int CurrentLength { get; set; }
        public string LastPassword { get; set; } = "";
        public long ProcessedCount { get; set; }
        public DateTime StartTime { get; set; }
        public HashSet<string> TriedPasswords { get; set; } = new();

        public void Save(string statePath)
        {
            var json = JsonSerializer.Serialize(this, new JsonSerializerOptions { WriteIndented = true });
            File.WriteAllText(statePath, json);
        }

        public static CrackState? Load(string statePath)
        {
            if (File.Exists(statePath))
            {
                var json = File.ReadAllText(statePath);
                return JsonSerializer.Deserialize<CrackState>(json);
            }
            return null;
        }
    }

    private class CrackOptions
    {
        public CrackMode Mode { get; set; }
        public string Password { get; set; } = "";
        public string DictionaryPath { get; set; } = "";
        public string Mask { get; set; } = "";
        public int MinLength { get; set; } = 1;
        public int MaxLength { get; set; } = 8;
        public bool UseDigits { get; set; }
        public bool UseLowerCase { get; set; }
        public bool UseUpperCase { get; set; }
        public bool UseSpecial { get; set; }
        public string CustomCharSet { get; set; } = "";
        public bool Resume { get; set; }
        public bool SaveState { get; set; }
        public int MaxMemoryMB { get; set; } = 1024;
        public string LogFile { get; set; } = "crack.log";
        public string FilePath { get; set; } = "";

        private string? _charset;
        public string Charset
        {
            get
            {
                if (_charset == null)
                {
                    var sb = new StringBuilder();
                    if (UseDigits) sb.Append("0123456789");
                    if (UseLowerCase) sb.Append("abcdefghijklmnopqrstuvwxyz");
                    if (UseUpperCase) sb.Append("ABCDEFGHIJKLMNOPQRSTUVWXYZ");
                    if (UseSpecial) sb.Append("!@#$%^&*()_+-=[]{}|;:,.<>?");
                    if (!string.IsNullOrEmpty(CustomCharSet)) sb.Append(CustomCharSet);
                    _charset = sb.ToString();
                }
                return _charset;
            }
            set
            {
                _charset = value;
            }
        }
    }

    private static void ShowHelp()
    {
        Console.WriteLine("Excel密码破解工具使用说明:");
        Console.WriteLine("\n基本用法:");
        Console.WriteLine("1. 单个密码模式:");
        Console.WriteLine("   ExcelUnlock <excel文件> -p <密码>");

        Console.WriteLine("\n2. 密码字典模式:");
        Console.WriteLine("   ExcelUnlock <excel文件> -f <密码文件>");

        Console.WriteLine("\n3. 暴力破解模式:");
        Console.WriteLine("   ExcelUnlock <excel文件> -b [选项]");
        Console.WriteLine("   选项:");
        Console.WriteLine("   -l, --min-length <数字>    最小密码长度 (默认: 1)");
        Console.WriteLine("   -L, --max-length <数字>    最大密码长度 (默认: 8)");
        Console.WriteLine("   -d, --digits              包含数字");
        Console.WriteLine("   -c, --lowercase           包含小写字母");
        Console.WriteLine("   -C, --uppercase           包含大写字母");
        Console.WriteLine("   -s, --special             包含特殊字符");
        Console.WriteLine("   --custom-charset <文件>    使用自定义字符集");

        Console.WriteLine("\n4. 掩码模式:");
        Console.WriteLine("   ExcelUnlock <excel文件> -m <掩码>");
        Console.WriteLine("   掩码规则:");
        Console.WriteLine("   ?d = 数字 (0-9)");
        Console.WriteLine("   ?l = 小写字母 (a-z)");
        Console.WriteLine("   ?u = 大写字母 (A-Z)");
        Console.WriteLine("   ?s = 特殊字符");
        Console.WriteLine("   ?a = ASCII可打印字符");
        Console.WriteLine("   ?h = 十六进制字符 (0-9, a-f)");
        Console.WriteLine("   ?1-?9 = 自定义字符集1-9");
        Console.WriteLine("   例如: ?d?d?d?d = 4位数字");

        Console.WriteLine("\n通用选项:");
        Console.WriteLine("   --resume                  从上次中断处继续");
        Console.WriteLine("   --save-state             保存破解状态（用于断点续传）");
        Console.WriteLine("   --max-memory <MB>        最大内存使用量（MB）");
        Console.WriteLine("   --log <文件>              指定日志文件");
    }

    private static string GetStateFilePath(string excelPath)
    {
        var fileName = Path.GetFileNameWithoutExtension(excelPath);
        return $"{fileName}_state.json";
    }

    private static void LogMessage(string message, string logFile)
    {
        var logMessage = $"[{DateTime.Now:yyyy-MM-dd HH:mm:ss}] {message}";
        Console.WriteLine(message);
        File.AppendAllText(logFile, logMessage + Environment.NewLine);
    }

    private static async Task<string?> LoadCustomCharSet(string? customCharSetPath)
    {
        if (string.IsNullOrEmpty(customCharSetPath) || !File.Exists(customCharSetPath))
            return null;

        try
        {
            return await File.ReadAllTextAsync(customCharSetPath);
        }
        catch (Exception ex)
        {
            Console.WriteLine($"加载自定义字符集时出错: {ex.Message}");
            return null;
        }
    }

    private static long GetAvailableMemory()
    {
        GC.Collect();
        return GC.GetTotalMemory(true);
    }

    private static void CheckMemoryUsage(long maxMemoryBytes)
    {
        var currentMemory = GetAvailableMemory();
        if (currentMemory > maxMemoryBytes)
        {
            GC.Collect();
            if (GetAvailableMemory() > maxMemoryBytes)
            {
                throw new OutOfMemoryException("内存使用超过限制");
            }
        }
    }

    private static async Task Main(string[] args)
    {
        try
        {
            var options = ParseCommandLineArgs(args);
            if (options == null || string.IsNullOrEmpty(options.FilePath))
            {
                ShowHelp();
                return;
            }

            var filePath = options.FilePath;
            if (!File.Exists(filePath))
            {
                Console.WriteLine($"错误: 文件 {filePath} 不存在");
                return;
            }

            Console.WriteLine($"\n开始破解文件: {filePath}");
            var sw = Stopwatch.StartNew();

            (bool found, string password) result = (false, "");

            switch (options.Mode)
            {
                case CrackMode.SinglePassword:
                    if (string.IsNullOrEmpty(options.Password))
                    {
                        Console.WriteLine("错误: 单密码模式需要指定密码");
                        return;
                    }
                    var (success, error) = await TryPassword(filePath, options.Password);
                    result = (success, options.Password);
                    break;

                case CrackMode.Dictionary:
                    if (string.IsNullOrEmpty(options.DictionaryPath))
                    {
                        Console.WriteLine("错误: 字典模式需要指定字典文件");
                        return;
                    }
                    result = await TryPasswordsFromFile(filePath, options);
                    break;

                case CrackMode.BruteForce:
                    result = await TryBruteForce(filePath, options);
                    break;

                case CrackMode.Mask:
                    if (string.IsNullOrEmpty(options.Mask))
                    {
                        Console.WriteLine("错误: 掩码模式需要指定掩码");
                        return;
                    }
                    result = await TryMaskMode(filePath, options);
                    break;
            }

            sw.Stop();
            Console.WriteLine($"\n破解完成!");
            Console.WriteLine($"总耗时: {sw.Elapsed.TotalSeconds:F2} 秒\n");

            if (result.found)
            {
                Console.WriteLine($"找到正确密码: {result.password}");
                await SaveUnencrypted(filePath, result.password);
            }
            else
            {
                Console.WriteLine("未找到正确密码");
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"发生错误: {ex.Message}");
            if (ex.InnerException != null)
            {
                Console.WriteLine($"详细错误: {ex.InnerException.Message}");
            }
        }
    }

    private static CrackOptions ParseCommandLineArgs(string[] args)
    {
        var options = new CrackOptions();

        for (int i = 0; i < args.Length; i++)
        {
            switch (args[i].ToLower())
            {
                case "-m":
                case "--mode":
                    if (i + 1 < args.Length)
                    {
                        if (Enum.TryParse<CrackMode>(args[++i], true, out var mode))
                        {
                            options.Mode = mode;
                        }
                    }
                    break;

                case "-f":
                case "--file":
                    if (i + 1 < args.Length)
                    {
                        options.FilePath = args[++i];
                    }
                    break;

                case "-p":
                case "--password":
                    if (i + 1 < args.Length)
                    {
                        options.Password = args[++i];
                    }
                    break;

                case "-d":
                case "--dictionary":
                    if (i + 1 < args.Length)
                    {
                        options.DictionaryPath = args[++i];
                    }
                    break;

                case "--mask":
                    if (i + 1 < args.Length)
                    {
                        options.Mask = args[++i];
                    }
                    break;

                case "--min":
                    if (i + 1 < args.Length && int.TryParse(args[++i], out var min))
                    {
                        options.MinLength = min;
                    }
                    break;

                case "--max":
                    if (i + 1 < args.Length && int.TryParse(args[++i], out var max))
                    {
                        options.MaxLength = max;
                    }
                    break;

                case "--charset":
                    if (i + 1 < args.Length)
                    {
                        options.Charset = args[++i];
                    }
                    break;

                case "--resume":
                    if (i + 1 < args.Length && bool.TryParse(args[++i], out var resume))
                    {
                        options.Resume = resume;
                    }
                    break;

                case "--save-state":
                    if (i + 1 < args.Length && bool.TryParse(args[++i], out var saveState))
                    {
                        options.SaveState = saveState;
                    }
                    break;
            }
        }

        return options;
    }

    public static object lockobj1 = new object();

    public static object lockobj2 = new object();

    private static async Task<(bool found, string password)> TryBruteForce(string filePath, CrackOptions options)
    {
        var startTime = DateTime.Now;
        var processed = 0;
        var found = false;
        var successPassword = "";
        var stateFilePath = GetStateFilePath(filePath);
        var triedPasswords = new HashSet<string>();
        CrackState currentState = null;

        // 如果是恢复模式，加载之前的状态
        if (options.Resume && File.Exists(stateFilePath))
        {
            currentState = CrackState.Load(stateFilePath);
            if (currentState != null)
            {
                processed = (int)currentState.ProcessedCount;
                found = currentState.LastPassword != "";
                successPassword = currentState.LastPassword;
                triedPasswords = currentState.TriedPasswords ?? new HashSet<string>();
                Console.WriteLine($"从上次中断处继续，已处理 {processed} 个密码");
            }
        }

        // 设置进度报告计时器
        var stopwatch = Stopwatch.StartNew();
        var progressTimer = new Timer(state =>
        {
            var elapsed = stopwatch.Elapsed.TotalSeconds;
            if (elapsed == 0) return;

            var speed = processed / elapsed;
            Console.WriteLine($"当前进度: 已尝试 {processed} 个密码, " +
                            $"速度: {speed:F2} 密码/秒");
        }, null, 1000, 1000);

        // 并行处理每个长度的密码
        for (int length = options.MinLength; length <= options.MaxLength && !found; length++)
        {
            Console.WriteLine($"\n开始尝试 {length} 位密码...");

            var currentPasswords = new string[] { string.Empty };

            for (int pos = 0; pos < length; pos++)
            {
                var newPasswords = new ConcurrentBag<string>();

                await Parallel.ForEachAsync(currentPasswords,
                    new ParallelOptions { MaxDegreeOfParallelism = Environment.ProcessorCount },
                    async (current, token) =>
                {
                    foreach (char c in options.Charset)
                    {
                        var newPassword = current + c;

                        lock (lockobj1)
                        {
                            newPasswords.Add(newPassword);
                        }

                        if (pos == length - 1)
                        {
                            if (!triedPasswords.Contains(newPassword))
                            {
                                lock (lockobj2)
                                {
                                    triedPasswords.Add(newPassword);
                                }
                                var (success, _) = await TryPassword(filePath, newPassword);
                                if (success)
                                {
                                    found = true;
                                    successPassword = newPassword;
                                    return;
                                }
                                Interlocked.Increment(ref processed);
                            }
                        }
                    }
                });

                if (found) break;
                currentPasswords = newPasswords.ToArray();
            }

            if (found) break;

            // 定期保存状态
            if (options.SaveState)
            {
                currentState = new CrackState
                {
                    FilePath = filePath,
                    Mode = CrackMode.BruteForce,
                    CurrentLength = length,
                    LastPassword = successPassword,
                    ProcessedCount = processed,
                    StartTime = startTime,
                    TriedPasswords = triedPasswords
                };
                currentState.Save(stateFilePath);
            }
        }

        // 停止进度报告
        await progressTimer.DisposeAsync();

        // 保存最终状态
        if (options.SaveState)
        {
            currentState = new CrackState
            {
                FilePath = filePath,
                Mode = CrackMode.BruteForce,
                CurrentLength = options.MaxLength,
                LastPassword = successPassword,
                ProcessedCount = processed,
                StartTime = startTime,
                TriedPasswords = triedPasswords
            };
            currentState.Save(stateFilePath);
        }

        return (found, successPassword);
    }

    private static async Task<(bool found, string password)> TryMaskMode(string filePath, CrackOptions options)
    {
        var startTime = DateTime.Now;
        var processed = 0;
        var found = false;
        var successPassword = "";
        var stateFilePath = GetStateFilePath(filePath);
        var triedPasswords = new HashSet<string>();
        CrackState currentState = null;

        // 如果是恢复模式，加载之前的状态
        if (options.Resume && File.Exists(stateFilePath))
        {
            currentState = CrackState.Load(stateFilePath);
            if (currentState != null)
            {
                processed = (int)currentState.ProcessedCount;
                found = currentState.LastPassword != "";
                successPassword = currentState.LastPassword;
                triedPasswords = currentState.TriedPasswords ?? new HashSet<string>();
                Console.WriteLine($"从上次中断处继续，已处理 {processed} 个密码");
            }
        }

        // 设置进度报告计时器
        var stopwatch = Stopwatch.StartNew();
        var progressTimer = new Timer(state =>
        {
            var elapsed = stopwatch.Elapsed.TotalSeconds;
            if (elapsed == 0) return;

            var speed = processed / elapsed;
            Console.WriteLine($"当前进度: 已尝试 {processed} 个密码, " +
                            $"速度: {speed:F2} 密码/秒");
        }, null, 1000, 1000);

        // 解析掩码
        var maskParts = new List<char[]>();
        for (int i = 0; i < options.Mask.Length; i++)
        {
            if (options.Mask[i] == '?' && i + 1 < options.Mask.Length)
            {
                char type = options.Mask[++i];
                char[] chars = type switch
                {
                    'd' => CharacterSets.Digits.ToCharArray(),
                    'l' => CharacterSets.LowerCase.ToCharArray(),
                    'u' => CharacterSets.UpperCase.ToCharArray(),
                    's' => CharacterSets.Special.ToCharArray(),
                    'a' => (CharacterSets.Digits + CharacterSets.LowerCase +
                           CharacterSets.UpperCase + CharacterSets.Special).ToCharArray(),
                    'h' => "0123456789abcdef".ToCharArray(),
                    _ => throw new ArgumentException($"未知的掩码类型: {type}")
                };
                maskParts.Add(chars);
            }
            else
            {
                maskParts.Add(new[] { options.Mask[i] });
            }
        }

        var currentPasswords = new string[] { string.Empty };

        // 生成所有可能的密码组合
        for (int pos = 0; pos < maskParts.Count && !found; pos++)
        {
            var newPasswords = new ConcurrentBag<string>();
            var charset = maskParts[pos];

            await Parallel.ForEachAsync(currentPasswords,
                new ParallelOptions { MaxDegreeOfParallelism = Environment.ProcessorCount },
                async (current, token) =>
            {
                foreach (char c in charset)
                {
                    var newPassword = current + c;
                    newPasswords.Add(newPassword);

                    if (pos == maskParts.Count - 1)
                    {
                        if (!triedPasswords.Contains(newPassword))
                        {
                            triedPasswords.Add(newPassword);
                            var (success, _) = await TryPassword(filePath, newPassword);
                            if (success)
                            {
                                found = true;
                                successPassword = newPassword;
                                return;
                            }
                            Interlocked.Increment(ref processed);
                        }
                    }
                }
            });

            if (found) break;
            currentPasswords = newPasswords.ToArray();

            // 定期保存状态
            if (options.SaveState)
            {
                currentState = new CrackState
                {
                    FilePath = filePath,
                    Mode = CrackMode.Mask,
                    CurrentLength = pos + 1,
                    LastPassword = successPassword,
                    ProcessedCount = processed,
                    StartTime = startTime,
                    TriedPasswords = triedPasswords
                };
                currentState.Save(stateFilePath);
            }
        }

        // 停止进度报告
        await progressTimer.DisposeAsync();

        // 保存最终状态
        if (options.SaveState)
        {
            currentState = new CrackState
            {
                FilePath = filePath,
                Mode = CrackMode.Mask,
                CurrentLength = maskParts.Count,
                LastPassword = successPassword,
                ProcessedCount = processed,
                StartTime = startTime,
                TriedPasswords = triedPasswords
            };
            currentState.Save(stateFilePath);
        }

        return (found, successPassword);
    }

    private static async Task<(bool found, string password)> TryPasswordsFromFile(string filePath, CrackOptions options)
    {
        try
        {
            if (!File.Exists(options.DictionaryPath))
            {
                Console.WriteLine($"错误: 密码字典文件不存在 - {options.DictionaryPath}");
                return (false, "");
            }

            var processed = 0;
            var startTime = DateTime.Now;
            var stopwatch = Stopwatch.StartNew();

            var progressTimer = new Timer(state =>
            {
                var elapsed = stopwatch.Elapsed.TotalSeconds;
                if (elapsed == 0) return;

                var speed = processed / elapsed;
                Console.WriteLine($"当前进度: 已尝试 {processed} 个密码, " +
                                $"速度: {speed:F2} 密码/秒");
            }, null, 1000, 1000);

            foreach (var password in File.ReadLines(options.DictionaryPath))
            {
                if (string.IsNullOrWhiteSpace(password)) continue;

                var (success, _) = await TryPassword(filePath, password);
                if (success)
                {
                    await progressTimer.DisposeAsync();
                    return (true, password);
                }

                processed++;
            }

            await progressTimer.DisposeAsync();
            return (false, "");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"处理密码字典时出错: {ex.Message}");
            return (false, "");
        }
    }

    private static async Task<(bool success, string error)> TryPassword(string filePath, string password)
    {
        try
        {
            Console.WriteLine("正在读取文件...");
            byte[] bytes = await File.ReadAllBytesAsync(filePath);
            using var stream = new MemoryStream(bytes);

            // 检查文件头部标识
            try
            {
                var header = new byte[8];
                stream.Read(header, 0, Math.Min(8, (int)stream.Length));
                stream.Position = 0;

                // 输出文件头部信息用于调试
                Console.WriteLine($"文件头部: {BitConverter.ToString(header)}");

                // 检查是否是OLE2格式 (D0-CF-11-E0-A1-B1-1A-E1)
                if (header[0] == 0xD0 && header[1] == 0xCF && header[2] == 0x11 && header[3] == 0xE0)
                {
                    Console.WriteLine("检测到OLE2格式的Excel文件");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"读取文件头部时出错: {ex.Message}");
            }

            try
            {
                Console.WriteLine("尝试验证密码...");
                var fs = new POIFSFileSystem(stream);

                // 检查是否有加密信息
                if (!fs.Root.HasEntry("EncryptionInfo"))
                {
                    Console.WriteLine("文件未加密，无需密码");
                    return (false, "文件未加密，无需密码");
                }

                try
                {
                    var info = new EncryptionInfo(fs);
                    Console.WriteLine($"加密类型: {info.VersionMajor}.{info.VersionMinor}");

                    var decryptor = Decryptor.GetInstance(info);
                    bool valid = decryptor.VerifyPassword(password);

                    if (valid)
                    {
                        using var document = decryptor.GetDataStream(fs);
                        // 尝试打开文件验证密码是否真的正确
                        using var workbook = new XSSFWorkbook(document);
                        return (true, string.Empty);
                    }
                    return (false, "密码错误");
                }
                catch (Exception ex) when (ex.Message.Contains("AgileEncryptionInfoBuilder"))
                {
                    Console.WriteLine("尝试其他解密方式...");
                    try
                    {
                        stream.Position = 0;
                        using var workbook = WorkbookFactory.Create(stream);
                        // 如果能打开，说明文件未加密
                        return (false, "文件未加密");
                    }
                    catch
                    {
                        // 文件可能是加密的，继续尝试
                        stream.Position = 0;
                        try
                        {
                            using var package = SpreadsheetDocument.Open(stream, false);
                            if (package.WorkbookPart != null)
                            {
                                return (false, "文件已损坏或使用了不支持的加密方式");
                            }
                            return (false, "未知错误");
                        }
                        catch
                        {
                            return (false, "密码错误或文件格式不正确");
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                return (false, $"验证密码时出错: {ex.Message}");
            }
        }
        catch (Exception ex)
        {
            return (false, $"处理文件时出错: {ex.Message}");
        }

        return (false, "未知错误");  // 确保所有路径都有返回值
    }

    private static async Task SaveUnencrypted(string filePath, string password)
    {
        try
        {
            Console.WriteLine("正在解密文件...");

            // 读取原始文件
            byte[] bytes = await File.ReadAllBytesAsync(filePath);
            using var stream = new MemoryStream(bytes);

            var fs = new POIFSFileSystem(stream);

            // 获取加密信息
            var info = new EncryptionInfo(fs);
            var decryptor = Decryptor.GetInstance(info);

            if (!decryptor.VerifyPassword(password))
            {
                Console.WriteLine("错误：密码验证失败，无法解密文件");
                return;
            }

            // 解密文件
            using var document = decryptor.GetDataStream(fs);
            using var workbook = new XSSFWorkbook(document);

            // 构建保存路径
            string directory = Path.GetDirectoryName(filePath) ?? "";
            string fileName = Path.GetFileNameWithoutExtension(filePath);
            string extension = Path.GetExtension(filePath);
            string newPath = Path.Combine(directory, $"{fileName}_已解密{extension}");

            // 确保文件名不重复
            int counter = 1;
            while (File.Exists(newPath))
            {
                newPath = Path.Combine(directory, $"{fileName}_已解密_{counter}{extension}");
                counter++;
            }

            Console.WriteLine($"正在保存解密后的文件到: {newPath}");

            // 保存解密后的文件
            using (var fileStream = File.Create(newPath))
            {
                workbook.Write(fileStream);
            }

            Console.WriteLine("文件解密成功！");
            Console.WriteLine($"解密后的文件已保存到: {newPath}");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"解密文件时出错: {ex.Message}");
            if (ex.InnerException != null)
            {
                Console.WriteLine($"详细错误: {ex.InnerException.Message}");
            }
        }
    }
}
