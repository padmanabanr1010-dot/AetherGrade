package database;

import java.sql.Connection;
import java.sql.DriverManager;

public class DBConnection {
    static final String URL = "jdbc:mysql://localhost:3306/studentgrademanager";
    static final String USER = "root";
    static final String PASSWORD = "padmanaban0$$";

    public static Connection getConnection() {
        try {
            Class.forName("com.mysql.cj.jdbc.Driver");
            return DriverManager.getConnection(URL, USER, PASSWORD);
        } catch (Exception e) {
            System.err.println("Database Connection Failed: " + e.getMessage());
            e.printStackTrace();
            return null;
        }
    }
}
