using Avalonia;
using Avalonia.Controls;
using Avalonia.Interactivity;
using Avalonia.Media;
using Avalonia.Threading;
using System;
using System.Diagnostics;
using System.Threading.Tasks;

namespace MyNetworkVisualizer
{
    public partial class NetworkManager : Window
    {
        public static event Action<bool>? NetworkStatusChanged;
        private const string StartScript = "/home/kali/new.sh";
        private const string StopScript = "/home/kali/stop.sh";

        public NetworkManager()
        {
            InitializeComponent();
            // Ստուգել վիճակը բացվելու պահին
            CheckInitialStatus();
        }

        private void CheckInitialStatus()
        {
            string status = RunSilentCommand("sudo ip netns exec nsA cat /sys/class/net/vA/operstate 2>/dev/null").Trim().ToLower();
            var toggle = this.FindControl<Avalonia.Controls.Primitives.ToggleButton>("NetworkToggle");
            
            if (status == "up" || status == "unknown")
            {
                if (toggle != null) toggle.IsChecked = true;
                UpdateUI("ՑԱՆՑԸ ԱԿՏԻՎ Է", Brushes.LimeGreen, "STOP NETWORK");
            }
        }

        private async void NetworkToggle_Checked(object sender, RoutedEventArgs e)
        {
            UpdateUI("Միանում է...", Brushes.Gold, "STARTING...");
            bool success = await Task.Run(() => RunBashScript(StartScript));
            if (success) {
                UpdateUI("ՑԱՆՑԸ ԱԿՏԻՎ Է", Brushes.LimeGreen, "STOP NETWORK");
                NetworkStatusChanged?.Invoke(true);
            }
        }

        private async void NetworkToggle_Unchecked(object sender, RoutedEventArgs e)
        {
            UpdateUI("Անջատվում է...", Brushes.Orange, "STOPPING...");
            await Task.Run(() => RunBashScript(StopScript));
            UpdateUI("Ցանցն Անջատված է", Brushes.Red, "START NETWORK");
            NetworkStatusChanged?.Invoke(false);
        }

        private bool RunBashScript(string path)
        {
            try {
                ProcessStartInfo psi = new ProcessStartInfo {
                    FileName = "sudo",
                    Arguments = $"bash {path}",
                    UseShellExecute = false,
                    CreateNoWindow = true
                };
                using (Process process = Process.Start(psi)) {
                    process?.WaitForExit();
                    return process?.ExitCode == 0;
                }
            } catch { return false; }
        }

        private string RunSilentCommand(string command)
        {
            try {
                ProcessStartInfo psi = new ProcessStartInfo {
                    FileName = "/bin/bash",
                    Arguments = $"-c \"{command}\"",
                    RedirectStandardOutput = true,
                    UseShellExecute = false,
                    CreateNoWindow = true
                };
                using (Process process = Process.Start(psi)) {
                    return process?.StandardOutput.ReadToEnd() ?? "";
                }
            } catch { return ""; }
        }

        private void UpdateUI(string status, IBrush color, string btnText)
        {
            Dispatcher.UIThread.Invoke(() => {
                StatusLabel.Text = status;
                StatusLed.Fill = color;
                NetworkToggle.Content = btnText;
            });
        }
    }
}