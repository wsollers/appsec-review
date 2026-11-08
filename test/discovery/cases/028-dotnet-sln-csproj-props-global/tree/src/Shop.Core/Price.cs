namespace Shop.Core;

public static class Price
{
    public static long Cents(long units) => units * 100;
}
