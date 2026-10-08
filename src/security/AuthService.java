package security;

import database.DBConnection;
import java.sql.*;

public class AuthService {

    public AuthService() {
        ensureUsersTableExists();
    }

    public void ensureUsersTableExists() {
        try (Connection con = DBConnection.getConnection()) {
            if (con == null) return;
            try (Statement st = con.createStatement()) {
                st.executeUpdate(
                    "CREATE TABLE IF NOT EXISTS users (" +
                    "username VARCHAR(50) PRIMARY KEY, " +
                    "password_hash VARCHAR(255) NOT NULL, " +
                    "role VARCHAR(20) NOT NULL, " +
                    "student_id INT NULL, " +
                    "created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP" +
                    ")"
                );
            } catch (SQLException ignored) {}

            try (Statement st = con.createStatement()) {
                st.executeUpdate(
                    "CREATE TABLE IF NOT EXISTS audit_logs (" +
                    "log_id INT AUTO_INCREMENT PRIMARY KEY, " +
                    "timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP, " +
                    "username VARCHAR(50), " +
                    "role VARCHAR(20), " +
                    "action VARCHAR(50) NOT NULL, " +
                    "resource VARCHAR(100), " +
                    "ip_address VARCHAR(45), " +
                    "status VARCHAR(20) NOT NULL, " +
                    "details TEXT" +
                    ")"
                );
            } catch (SQLException ignored) {}

            seedDefaultUsers(con);
        } catch (Exception e) {
            System.err.println("Auth Table Initialization Notice: " + e.getMessage());
        }
    }

    private void seedDefaultUsers(Connection con) {
        try {
            seedUserIfMissing(con, "admin", "admin123", "ADMIN", null);
            seedUserIfMissing(con, "faculty", "faculty123", "FACULTY", null);
        } catch (Exception e) {
            System.err.println("Default user seeding notice: " + e.getMessage());
        }
    }

    private void seedUserIfMissing(Connection con, String username, String plainPassword, String role, Integer studentId) throws SQLException {
        String checkSql = "SELECT 1 FROM users WHERE username = ?";
        try (PreparedStatement ps = con.prepareStatement(checkSql)) {
            ps.setString(1, username);
            try (ResultSet rs = ps.executeQuery()) {
                if (!rs.next()) {
                    String insertSql = "INSERT INTO users (username, password_hash, role, student_id) VALUES (?, ?, ?, ?)";
                    try (PreparedStatement insertPs = con.prepareStatement(insertSql)) {
                        insertPs.setString(1, username);
                        insertPs.setString(2, PasswordHasher.hashPassword(plainPassword));
                        insertPs.setString(3, role);
                        if (studentId != null) {
                            insertPs.setInt(4, studentId);
                        } else {
                            insertPs.setNull(4, Types.INTEGER);
                        }
                        insertPs.executeUpdate();
                        System.out.println("Seeded default user: " + username + " (" + role + ")");
                    }
                }
            }
        }
    }

    public static class LoginResult {
        private final boolean success;
        private final String message;
        private final String token;
        private final String username;
        private final String role;
        private final Integer studentId;

        public LoginResult(boolean success, String message, String token, String username, String role, Integer studentId) {
            this.success = success;
            this.message = message;
            this.token = token;
            this.username = username;
            this.role = role;
            this.studentId = studentId;
        }

        public boolean isSuccess() { return success; }
        public String getMessage() { return message; }
        public String getToken() { return token; }
        public String getUsername() { return username; }
        public String getRole() { return role; }
        public Integer getStudentId() { return studentId; }

        public String toJson() {
            return String.format(
                "{\"success\":%b,\"message\":\"%s\",\"token\":%s,\"username\":%s,\"role\":%s,\"studentId\":%s}",
                success,
                escapeJson(message),
                token == null ? "null" : "\"" + escapeJson(token) + "\"",
                username == null ? "null" : "\"" + escapeJson(username) + "\"",
                role == null ? "null" : "\"" + escapeJson(role) + "\"",
                studentId == null ? "null" : studentId.toString()
            );
        }

        private String escapeJson(String s) {
            if (s == null) return "";
            return s.replace("\\", "\\\\").replace("\"", "\\\"");
        }
    }

    public LoginResult authenticate(String username, String password) {
        if (username == null || password == null || username.trim().isEmpty() || password.trim().isEmpty()) {
            return new LoginResult(false, "Username and password are required", null, null, null, null);
        }

        String sql = "SELECT username, password_hash, role, student_id FROM users WHERE username = ?";
        try (Connection con = DBConnection.getConnection();
             PreparedStatement ps = con.prepareStatement(sql)) {
            
            ps.setString(1, username.trim());
            try (ResultSet rs = ps.executeQuery()) {
                if (rs.next()) {
                    String storedHash = rs.getString("password_hash");
                    String role = rs.getString("role");
                    int sIdRaw = rs.getInt("student_id");
                    Integer studentId = rs.wasNull() ? null : sIdRaw;

                    if ("STUDENT".equalsIgnoreCase(role)) {
                        return new LoginResult(false, "Access Denied: Application is restricted to Faculty and Admin only.", null, null, null, null);
                    }

                    if (PasswordHasher.verifyPassword(password, storedHash)) {
                        String token = JwtUtil.generateToken(username, role, studentId);
                        return new LoginResult(true, "Authentication successful", token, username, role, studentId);
                    }
                }
            }
        } catch (Exception e) {
            System.err.println("Authentication error: " + e.getMessage());
        }

        return new LoginResult(false, "Invalid username or password", null, null, null, null);
    }
}
