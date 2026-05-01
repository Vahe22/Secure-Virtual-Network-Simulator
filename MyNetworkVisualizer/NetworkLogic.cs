using System;
using System.Diagnostics;
using System.IO;

public class NetworkLogic {
    // Հասցեները ըստ քո համակարգչի դասավորության
    private string backendPath = "/home/vahe/Desktop/MyProj/C_backend";
    private string homePath = "/home/vahe";

    public void PrepareEverything() {
        // 1. Կոմպիլյացիա (make)
        Process.Start(new ProcessStartInfo { 
            FileName = "make", WorkingDirectory = backendPath 
        })?.WaitForExit();

        // 2. Բանալիների ստեղծում
        Process.Start($"{backendPath}/provisioner", $"{backendPath}/dev1_keys")?.WaitForExit();
        Process.Start($"{backendPath}/provisioner", $"{backendPath}/dev2_keys")?.WaitForExit();
        
        // 3. Պատճենել հանրային բանալիները (Peer keys)
        File.Copy($"{backendPath}/dev1_keys/identity_pub.pem", $"{backendPath}/dev2_keys/peer_identity_pub.pem", true);
        File.Copy($"{backendPath}/dev2_keys/identity_pub.pem", $"{backendPath}/dev1_keys/peer_identity_pub.pem", true);
    }

    public Process StartNode(int id) {
        ProcessStartInfo psi = new ProcessStartInfo {
            FileName = "sudo",
            Arguments = $"ip netns exec nsD{id} {backendPath}/dev{id}_bin",
            RedirectStandardOutput = true,
            UseShellExecute = false,
            CreateNoWindow = true
        };
        Process p = new Process { StartInfo = psi };
        p.Start();
        return p;
    }
}