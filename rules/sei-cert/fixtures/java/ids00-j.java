// SEI CERT IDS00-J focused fixture.
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

class Users {
    ResultSet byName(Connection connection, String name) throws SQLException {
        Statement statement = connection.createStatement();
        // cert: positive appsec-review.sei-cert.java.ids00-j.concatenated-sql-statement
        return statement.executeQuery("SELECT * FROM users WHERE name = '" + name + "'");
    }

    int deleteById(Connection connection, String id) throws SQLException {
        String sql = "DELETE FROM users WHERE id = " + id;
        // cert: variant appsec-review.sei-cert.java.ids00-j.concatenated-sql-statement
        return connection.createStatement().executeUpdate(sql);
    }

    PreparedStatement prepared(Connection connection, String order) throws SQLException {
        // cert: variant appsec-review.sei-cert.java.ids00-j.concatenated-sql-statement
        return connection.prepareStatement("SELECT * FROM users ORDER BY " + order);
    }

    ResultSet parameterized(Connection connection, String name) throws SQLException {
        PreparedStatement statement = connection.prepareStatement("SELECT * FROM users WHERE name = ?");
        statement.setString(1, name);
        // cert: safe-alternative appsec-review.sei-cert.java.ids00-j.concatenated-sql-statement
        return statement.executeQuery();
    }

    ResultSet constant(Connection connection) throws SQLException {
        // cert: near-miss appsec-review.sei-cert.java.ids00-j.concatenated-sql-statement
        return connection.createStatement().executeQuery("SELECT * FROM users " + "WHERE active = 1");
    }

    void log(StringBuilder buffer, String name) {
        // cert: negative appsec-review.sei-cert.java.ids00-j.concatenated-sql-statement
        buffer.append("user=" + name);
    }
}
