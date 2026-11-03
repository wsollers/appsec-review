package demo;

import java.util.List;

public class Spans {
    private int limit = 3; // ANCHOR:none

    public Spans(int value) { // BEGIN:ctor
        this.limit = value; // ANCHOR:ctor
    } // END:ctor

    public int count(List<String> items) { // BEGIN:count
        int total = 0;
        items.forEach(item -> {
            System.out.println(item); // ANCHOR:count
        });
        synchronized (this) {
            total = items.size(); // ANCHOR:count
        }
        return total;
    } // END:count
}
