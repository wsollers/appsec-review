using System;
using System.IO;
using System.Text;

public static class WslStandin
{
    public static int Main(string[] args)
    {
        string[] encoded = new string[args.Length];
        for (int i = 0; i < args.Length; i++)
            encoded[i] = Convert.ToBase64String(Encoding.UTF8.GetBytes(args[i]));
        File.AppendAllText(
            Environment.GetEnvironmentVariable("APPSEC_ACCEPTANCE_WSL_ARGS"),
            String.Join("|", encoded) + Environment.NewLine);
        if (args.Length > 3 && args[3] == "wslpath")
        {
            Console.WriteLine("/mnt/c/fixture with spaces/operator.sh");
            return 0;
        }
        return 37;
    }
}
