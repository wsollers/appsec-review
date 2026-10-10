package com.example.store;

import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.Connection;

public class UserStore {
    private Connection connection;

    public void save(String name, Path audit) throws Exception {
        connection.setAutoCommit(false);
        connection.createStatement().executeUpdate("INSERT INTO users VALUES ('" + name + "')");
        Files.writeString(audit, name);
        connection.commit();
    }
}
