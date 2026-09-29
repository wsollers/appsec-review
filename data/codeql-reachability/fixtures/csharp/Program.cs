using Example.Vuln;

public static class Program
{
    static string Handle(string input) => Parser.Parse(input);

    public static void Main(string[] args) => System.Console.WriteLine(Handle(args[0]));
}
