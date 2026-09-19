package com.example;

public final class Hello {
    private Hello() {
    }

    public static void main(String[] args) {
        System.out.println(message());
    }

    public static String message() {
        return "hello from java";
    }
}
