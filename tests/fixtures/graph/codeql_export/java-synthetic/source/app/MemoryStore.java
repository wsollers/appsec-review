package app;

import java.util.ArrayList;
import java.util.List;

public class MemoryStore implements Store {
    private final List<String> names = new ArrayList<>();

    @Override
    public void save(String name) {
        names.add(name);
    }
}
