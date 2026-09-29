package app;

import com.example.vuln.Parser;

public class Main {
    static String handle(String input) { return Parser.parse(input); }

    public static void main(String[] args) { System.out.println(handle(args[0])); }
}
