package smoke;

public class Main {
    static int helper(int value) {
        return value + 1;
    }

    public static void main(String[] args) {
        System.exit(helper(41) == 42 ? 0 : 1);
    }
}
