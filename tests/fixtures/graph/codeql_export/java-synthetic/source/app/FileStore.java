package app;

import java.io.FileOutputStream;

public class FileStore implements Store {
    @Override
    public void save(String name) throws Exception {
        new FileOutputStream(name).close();
    }
}
