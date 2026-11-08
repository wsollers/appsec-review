using System.Runtime.InteropServices;

public static class Bridge
{
    [DllImport("nativeplugin")]
    public static extern int plugin_version();
}
