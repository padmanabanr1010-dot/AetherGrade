package audit;

import database.DBConnection;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class AuditLogger {
    private static final ExecutorService asyncLogQueue = Executors.newSingleThreadExecutor(r -> {
        Thread t = new Thread(r, "AsyncAuditLoggerWorker");
        t.setDaemon(true);
        return t;
    });

    public static void log(String username, String role, String action, String resource, String ipAddress, String status, String details) {
        asyncLogQueue.submit(() -> {
            String sql = "INSERT INTO audit_logs (username, role, action, resource, ip_address, status, details) VALUES (?, ?, ?, ?, ?, ?, ?)";
            try (Connection con = DBConnection.getConnection();
                 PreparedStatement ps = con.prepareStatement(sql)) {
                
                ps.setString(1, username == null ? "ANONYMOUS" : username);
                ps.setString(2, role == null ? "GUEST" : role);
                ps.setString(3, action);
                ps.setString(4, resource);
                ps.setString(5, ipAddress == null ? "UNKNOWN" : ipAddress);
                ps.setString(6, status);
                ps.setString(7, details);

                ps.executeUpdate();
            } catch (Exception e) {
                System.err.println("Failed to write async audit log: " + e.getMessage());
            }
        });
    }
}
