using System;
using System.Diagnostics;
using System.Threading;

class Program
{
    static void Main(string[] args)
    {
        Console.WriteLine("=== Secure Virtual Network Monitor ===");
        
        // Անվերջ ցիկլ՝ իրական ժամանակում մոնիտորինգի համար
        while (true)
        {
            Console.Clear();
            Console.WriteLine($"Time: {DateTime.Now:HH:mm:ss}");
            Console.WriteLine("-------------------------------------");

            // 1. Ստուգում ենք՝ արդյոք Namespaces-ները ստեղծված են
            string namespaces = ExecuteLinuxCommand("ip netns list");
            
            // 2. Ստուգում ենք կապի վիճակը (vA ինտերֆեյսը nsA-ում)
            string linkStatus = ExecuteLinuxCommand("ip netns exec nsA cat /sys/class/net/vA/operstate 2>/dev/null");

            // Վիզուալիզացիա տերմինալում
            DisplayTopology(namespaces, linkStatus);

            // Սպասում ենք 1 վայրկյան հաջորդ թարմացումից առաջ
            Thread.Sleep(1000);
        }
    }

    static void DisplayTopology(string namespaces, string status)
    {
        bool isActive = namespaces.Contains("nsA") && namespaces.Contains("nsB");
        string color = (status == "up") ? "[GREEN]" : "[RED]";

        Console.WriteLine("DEVICE TOPOLOGY:");
        
        if (isActive)
        {
            // Սա քո ցանցի վիզուալ պատկերն է տերմինալում
            Console.WriteLine($"  [nsA] <--- {color}(vA) ---> [nsD1] <---> [nsD2] <---> [nsB]");
            Console.WriteLine($"\nLink Status: {status.ToUpper()}");
        }
        else
        {
            Console.WriteLine("  [!] Devices not detected. Please run your Bash script.");
        }
    }

    public static string ExecuteLinuxCommand(string command)
    {
        ProcessStartInfo psi = new ProcessStartInfo
        {
            FileName = "/bin/bash",
            Arguments = $"-c \"{command}\"", 
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true
        };

        using (Process process = Process.Start(psi))
        {
            string output = process.StandardOutput.ReadToEnd();
            process.WaitForExit();
            return output.Trim();
        }
    }
}