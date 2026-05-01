using Avalonia;
using Avalonia.Controls.ApplicationLifetimes;
using Avalonia.Markup.Xaml;

namespace MyNetworkVisualizer;

public partial class App : Application
{
    public override void Initialize() => AvaloniaXamlLoader.Load(this);

    public override void OnFrameworkInitializationCompleted()
    {
        if (ApplicationLifetime is IClassicDesktopStyleApplicationLifetime desktop)
        {
            desktop.MainWindow = new MainWindow();
            var nm = new NetworkManager();
            nm.Position = new PixelPoint(950, 200); 
            nm.Show();
        }
        base.OnFrameworkInitializationCompleted();
    }
}