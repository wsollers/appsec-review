namespace Smoke;

public static class Program
{
    static int Helper(int value) => value + 1;

    public static int Main() => Helper(41) == 42 ? 0 : 1;
}
