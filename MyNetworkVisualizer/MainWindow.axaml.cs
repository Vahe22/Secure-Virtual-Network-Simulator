using Avalonia;
using Avalonia.Controls;
using Avalonia.Media;
using Avalonia.Threading;
using Avalonia.Interactivity;
using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Threading.Tasks;

namespace MyNetworkVisualizer
{
    public partial class MainWindow : Window
    {
        private bool _isChecking = false;
        private bool _systemRunning = false;
        private Process? _d1Process, _d2Process, _receiverProcess;

        private static readonly string UserHome = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        private readonly string _backendPath = Path.Combine(UserHome, "Desktop/MyProj/C_backend");
        private readonly string _startScript = Path.Combine(UserHome, "new.sh");
        private readonly string _stopScript = Path.Combine(UserHome, "stop.sh");

        public MainWindow()
        {
            InitializeComponent();
            DispatcherTimer.Run(() => {
                if (_systemRunning && !_isChecking) { _ = UpdateNetworkStatus(); }
                return true;
            }, TimeSpan.FromSeconds(2));
        }

        public async void StartBtn_Click(object sender, RoutedEventArgs e)
        {
            if (_systemRunning) return;
            _systemRunning = true;
            StartBtn.IsEnabled = false;

            try {
                Log("🚀 Initializing Environment...");
                ExecuteLinuxCommandWithStderr($"sudo chown -R {Environment.UserName}:{Environment.UserName} \"{_backendPath}\"");
                
                Log("🌐 Creating Virtual Network Interfaces...");
                ExecuteLinuxCommandWithStderr($"sudo bash \"{_startScript}\"");
                await Task.Delay(1000);

                Log("🔧 Applying Network Hotfixes (MTU & Offloading)...");
                string[] interfaces = { "nsA vA", "nsB vB", "nsD1 vD1L", "nsD1 vD1R", "nsD2 vD2L", "nsD2 vD2R" };
                foreach (var inf in interfaces) {
                    var parts = inf.Split(' ');
                    ExecuteLinuxCommandWithStderr($"sudo ip netns exec {parts[0]} ip link set {parts[1]} mtu 2000");
                    ExecuteLinuxCommandWithStderr($"sudo ip netns exec {parts[0]} ethtool -K {parts[1]} tx off rx off 2>/dev/null");
                }

                Log("🔨 Rebuilding Backend Binaries...");
                ExecuteLinuxCommandWithStderr("make clean && make");

                Log("🔑 Provisioning Security Keys...");
                ExecuteLinuxCommandWithStderr("rm -rf dev1_keys dev2_keys && mkdir -p dev1_keys dev2_keys");
                ExecuteLinuxCommandWithStderr("./provisioner dev1_keys && ./provisioner dev2_keys");
                
                string k1 = Path.Combine(_backendPath, "dev1_keys/identity_pub.pem");
                string k2 = Path.Combine(_backendPath, "dev2_keys/identity_pub.pem");

                await Task.Delay(1500); 
                if (!File.Exists(k1) || !File.Exists(k2)) {
                    throw new Exception("Cryptographic keys were not generated.");
                }

                File.Copy(k1, Path.Combine(_backendPath, "dev2_keys/peer_identity_pub.pem"), true);
                File.Copy(k2, Path.Combine(_backendPath, "dev1_keys/peer_identity_pub.pem"), true);
                Log("✅ Public Keys Successfully Swapped.");

                Log("🛰️ Configuring Routing & Forwarding...");
                ExecuteLinuxCommandWithStderr("sudo sysctl -w net.ipv4.ip_forward=1");
                ExecuteLinuxCommandWithStderr("sudo ip netns exec nsA ip route replace 10.20.20.2 dev vA scope link");
                ExecuteLinuxCommandWithStderr("sudo ip netns exec nsB ip route replace 10.20.20.1 dev vB scope link");

                string macB = ExecuteLinuxCommandWithStderr("sudo ip netns exec nsB cat /sys/class/net/vB/address").Trim();
                if (!string.IsNullOrEmpty(macB) && !macB.Contains("ERROR")) {
                    ExecuteLinuxCommandWithStderr($"sudo ip netns exec nsA ip neighbor replace 10.20.20.2 lladdr {macB} dev vA");
                }
                
                string macA = ExecuteLinuxCommandWithStderr("sudo ip netns exec nsA cat /sys/class/net/vA/address").Trim();
                if (!string.IsNullOrEmpty(macA) && !macA.Contains("ERROR")) {
                    ExecuteLinuxCommandWithStderr($"sudo ip netns exec nsB ip neighbor replace 10.20.20.1 lladdr {macA} dev vB");
                }

                Log("🛡️ Launching Tunnel Nodes (D1 & D2)...");
                _d1Process = StartCNode(1, "nsD1", "./dev1_bin");
                _d2Process = StartCNode(2, "nsD2", "./dev2_bin");
                
                Dispatcher.UIThread.Post(() => {
                    StatusLabel.Text = "WAITING FOR HANDSHAKE...";
                    StatusDot.Fill = Brushes.Orange;
                });
            } catch (Exception ex) {
                Log($"❌ START ERROR: {ex.Message}");
                _systemRunning = false;
                Dispatcher.UIThread.Post(() => StartBtn.IsEnabled = true);
            }
        }

        public async void SendBtn_Click(object sender, RoutedEventArgs e)
        {
            string msg = MessageInput.Text;
            if (string.IsNullOrWhiteSpace(msg) || !_systemRunning) return;

            try {
                Log("🔁 Restarting Receiver to accept new message...");
                try { _receiverProcess?.Kill(); } catch { }
                ExecuteLinuxCommandWithStderr("sudo rm -f out.bin"); // Ջնջում ենք հինը
                
                // Միացնում ենք Receiver-ը թարմ վիճակով
                _receiverProcess = StartCNode(3, "nsB", "./receiver 40000 out.bin");
                await Task.Delay(500); // Սպասում ենք, որ Port 40000-ը բացվի

                string tempFile = Path.Combine(_backendPath, "msg.txt");
                File.WriteAllText(tempFile, msg);
                Log("🚀 Sending secure payload...");
                
                // Անիմացիան միացնում ենք
                _ = AnimatePacket();

                // Ուղարկում ենք փաթեթը
                string result = ExecuteLinuxCommandWithStderr($"sudo ip netns exec nsA ./sender 10.20.20.2 40000 \"{tempFile}\"");
                if (!string.IsNullOrWhiteSpace(result)) {
                    Log($"[SENDER]: {result.Trim()}");
                }
                
                MessageInput.Clear();

                // ԿԱՐԵՎՈՐ: Սպասում ենք և կարդում ենք վերջնական ֆայլը, որ ցույց տանք էկրանին
                await Task.Delay(1000); 
                string decodedMsg = ExecuteLinuxCommandWithStderr("sudo cat out.bin").Trim();
                
                if (!string.IsNullOrEmpty(decodedMsg) && !decodedMsg.Contains("No such file")) {
                    Dispatcher.UIThread.Post(() => {
                        DecryptedOutput.Text = decodedMsg;
                        Log("✅ Message securely arrived and decrypted!");
                    });
                } else {
                    Log("⚠️ Warning: Could not read out.bin.");
                }

            } catch (Exception ex) {
                Log($"❌ SEND ERROR: {ex.Message}");
            }
        }

        private Process StartCNode(int id, string ns, string binCmd)
        {
            ProcessStartInfo psi = new ProcessStartInfo {
                FileName = "sudo",
                Arguments = $"ip netns exec {ns} {binCmd}",
                RedirectStandardOutput = true,
                RedirectStandardError = true, 
                UseShellExecute = false,
                CreateNoWindow = true,
                WorkingDirectory = _backendPath 
            };

            Process p = new Process { StartInfo = psi };
            p.OutputDataReceived += (s, e) => {
                if (!string.IsNullOrEmpty(e.Data)) Dispatcher.UIThread.Post(() => HandleCLog(id, e.Data));
            };
            p.ErrorDataReceived += (s, e) => {
                if (!string.IsNullOrEmpty(e.Data)) Dispatcher.UIThread.Post(() => HandleCLog(id, e.Data));
            };
            p.Start();
            p.BeginOutputReadLine();
            p.BeginErrorReadLine();
            return p;
        }

        private void HandleCLog(int id, string data)
        {
            string cleanData = data.ToLower();
            
            // Կողպեքների վիզուալիզացիա
            if (cleanData.Contains("session established")) {
                Log($"🔒 Node {id}: Securely Connected.");
                Dispatcher.UIThread.Post(() => {
                    if (id == 1) LockD1.Text = "🔒";
                    if (id == 2) LockD2.Text = "🔒";
                    
                    if (LockD1.Text == "🔒" && LockD2.Text == "🔒") {
                        StatusLabel.Text = "SECURE END-TO-END CHANNEL ACTIVE";
                        StatusDot.Fill = Brushes.LimeGreen;
                    }
                });
                return;
            }
            
            // Էնտրոպիայի վիզուալիզացիա (Օգտագործում ենք Contains, որ հաստատ բռնի)
            if (data.Contains("ENTROPY_DATA:")) {
                try {
                    int index = data.IndexOf("ENTROPY_DATA:") + 13;
                    string hex = data.Substring(index).Trim();
                    Dispatcher.UIThread.Post(() => CipherOutput.Text = hex);
                    
                    byte[] bytes = HexToByte(hex);
                    double entropy = CalculateEntropy(bytes);
                    
                    Dispatcher.UIThread.Post(() => {
                        EntropyValue.Text = entropy.ToString("F2");
                        EntropyBar.Value = entropy;
                    });
                } catch { }
                return;
            }

            // Սովորական լոգեր
            Log($"[DEV{id}]: {data}");
        }

        private double CalculateEntropy(byte[] data)
        {
            if (data.Length == 0) return 0;
            var counts = new double[256];
            foreach (byte b in data) counts[b]++;
            double entropy = 0;
            foreach (var c in counts) {
                if (c > 0) {
                    double p = c / data.Length;
                    entropy -= p * Math.Log(p, 2);
                }
            }
            return entropy;
        }

        private byte[] HexToByte(string hex) => Enumerable.Range(0, hex.Length / 2)
            .Select(x => Convert.ToByte(hex.Substring(x * 2, 2), 16)).ToArray();

        private void Log(string msg) {
            Dispatcher.UIThread.Post(() => {
                LogText.Text += $"{msg}\n";
                LogScroller.ScrollToEnd();
            });
        }

        private string ExecuteLinuxCommandWithStderr(string cmd)
        {
            try {
                var psi = new ProcessStartInfo {
                    FileName = "/bin/bash",
                    Arguments = $"-c \"cd '{_backendPath}' && {cmd}\"",
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    UseShellExecute = false,
                    CreateNoWindow = true
                };
                using (var p = Process.Start(psi)) {
                    string output = p?.StandardOutput.ReadToEnd() ?? "";
                    string error = p?.StandardError.ReadToEnd() ?? "";
                    p?.WaitForExit();
                    return string.IsNullOrEmpty(error) ? output : $"{output}\nERROR: {error}".Trim();
                }
            } catch (Exception ex) { return $"CRITICAL CMD ERROR: {ex.Message}"; }
        }

        public void StopBtn_Click(object sender, RoutedEventArgs e)
        {
            _systemRunning = false;
            
            try { _d1Process?.Kill(); } catch { }
            try { _d2Process?.Kill(); } catch { }
            try { _receiverProcess?.Kill(); } catch { }
            
            ExecuteLinuxCommandWithStderr($"sudo bash \"{_stopScript}\"");
            
            Dispatcher.UIThread.Post(() => {
                StatusLabel.Text = "OFFLINE"; 
                StatusDot.Fill = Brushes.Gray;
                LockD1.Text = "🔓"; 
                LockD2.Text = "🔓";
                StartBtn.IsEnabled = true;
            });
            Log("🛑 System Shutdown Complete.");
        }

        private async Task UpdateNetworkStatus()
        {
            if (_isChecking || !_systemRunning) return;
            _isChecking = true;
            
            string res = ExecuteLinuxCommandWithStderr("sudo ip netns exec nsA cat /sys/class/net/vA/operstate 2>/dev/null").Trim().ToLower();
            if (res.Contains("up") || res.Contains("unknown")) {
                Dispatcher.UIThread.Post(() => StatusDot.Fill = Brushes.LimeGreen);
            }
            
            _isChecking = false;
        }

        private async Task AnimatePacket()
        {
            var transform = Packet.RenderTransform as TranslateTransform;
            if (transform == null || !_systemRunning || Packet.Opacity > 0) return;
            
            Dispatcher.UIThread.Post(() => Packet.Opacity = 1);
            await MoveTo(transform, 100, 150, 340, 150, 15);
            Dispatcher.UIThread.Post(() => Packet.Background = Brushes.Cyan);
            await MoveTo(transform, 340, 150, 550, 150, 20);
            Dispatcher.UIThread.Post(() => Packet.Background = Brushes.White);
            await MoveTo(transform, 550, 150, 800, 150, 15);
            Dispatcher.UIThread.Post(() => Packet.Opacity = 0);
        }

        private async Task MoveTo(TranslateTransform t, double sX, double sY, double eX, double eY, int steps)
        {
            for (int i = 0; i <= steps; i++) {
                if (!_systemRunning) return;
                
                Dispatcher.UIThread.Post(() => {
                    t.X = sX + (eX - sX) * i / steps;
                    t.Y = sY + (eY - sY) * i / steps;
                });
                
                await Task.Delay(30);
            }
        }
    }
}