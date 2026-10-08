package audit;

import database.DBConnection;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.sql.*;
import java.util.ArrayList;
import java.util.List;

public class AuditLedgerUtil {

    public static final String GENESIS_HASH = "0000000000000000000000000000000000000000000000000000000000000000";

    public static class LedgerEntry {
        private final int id;
        private final Timestamp timestamp;
        private final String actorId;
        private final String actionType;
        private final int recordId;
        private final String dataPayload;
        private final String previousHash;
        private final String currentHash;

        public LedgerEntry(int id, Timestamp timestamp, String actorId, String actionType, int recordId, String dataPayload, String previousHash, String currentHash) {
            this.id = id;
            this.timestamp = timestamp;
            this.actorId = actorId;
            this.actionType = actionType;
            this.recordId = recordId;
            this.dataPayload = dataPayload;
            this.previousHash = previousHash;
            this.currentHash = currentHash;
        }

        public int getId() { return id; }
        public Timestamp getTimestamp() { return timestamp; }
        public String getActorId() { return actorId; }
        public String getActionType() { return actionType; }
        public int getRecordId() { return recordId; }
        public String getDataPayload() { return dataPayload; }
        public String getPreviousHash() { return previousHash; }
        public String getCurrentHash() { return currentHash; }

        public String toJson() {
            return String.format(java.util.Locale.US,
                "{\"id\":%d,\"timestamp\":\"%s\",\"actorId\":\"%s\",\"actionType\":\"%s\",\"recordId\":%d,\"dataPayload\":\"%s\",\"previousHash\":\"%s\",\"currentHash\":\"%s\"}",
                id,
                timestamp != null ? timestamp.toString() : "",
                escapeJson(actorId),
                escapeJson(actionType),
                recordId,
                escapeJson(dataPayload),
                escapeJson(previousHash),
                escapeJson(currentHash)
            );
        }

        private static String escapeJson(String s) {
            if (s == null) return "";
            return s.replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", "\\n").replace("\r", "\\r");
        }
    }

    public static class VerificationResult {
        private final boolean valid;
        private final String status; // "SECURE" or "TAMPER_DETECTED"
        private final int brokenRowId;
        private final int totalRecords;
        private final String details;

        public VerificationResult(boolean valid, String status, int brokenRowId, int totalRecords, String details) {
            this.valid = valid;
            this.status = status;
            this.brokenRowId = brokenRowId;
            this.totalRecords = totalRecords;
            this.details = details;
        }

        public boolean isValid() { return valid; }
        public String getStatus() { return status; }
        public int getBrokenRowId() { return brokenRowId; }
        public int getTotalRecords() { return totalRecords; }
        public String getDetails() { return details; }

        public String toJson() {
            return String.format(java.util.Locale.US,
                "{\"valid\":%b,\"status\":\"%s\",\"brokenRowId\":%d,\"totalRecords\":%d,\"details\":\"%s\"}",
                valid, status, brokenRowId, totalRecords, escapeJson(details)
            );
        }

        private static String escapeJson(String s) {
            if (s == null) return "";
            return s.replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", "\\n").replace("\r", "\\r");
        }
    }

    public static void ensureTableExists() {
        try (Connection con = DBConnection.getConnection()) {
            if (con == null) return;
            ensureTableExists(con);
        } catch (Exception e) {
            System.err.println("AuditLedger table initialization notice: " + e.getMessage());
        }
    }

    public static void ensureTableExists(Connection con) throws SQLException {
        String sql = "CREATE TABLE IF NOT EXISTS audit_ledger (" +
                "id INT AUTO_INCREMENT PRIMARY KEY, " +
                "timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP, " +
                "actor_id VARCHAR(50) NOT NULL, " +
                "action_type VARCHAR(50) NOT NULL, " +
                "record_id INT NOT NULL, " +
                "data_payload TEXT NOT NULL, " +
                "previous_hash VARCHAR(64) NOT NULL, " +
                "current_hash VARCHAR(64) NOT NULL" +
                ")";
        try (Statement st = con.createStatement()) {
            st.executeUpdate(sql);
        }
    }

    public static synchronized LedgerEntry appendBlock(String actorId, String actionType, int recordId, String dataPayload) {
        try (Connection con = DBConnection.getConnection()) {
            if (con == null) return null;
            return appendBlock(con, actorId, actionType, recordId, dataPayload);
        } catch (Exception e) {
            System.err.println("Failed to append block to audit ledger: " + e.getMessage());
            e.printStackTrace();
            return null;
        }
    }

    public static synchronized LedgerEntry appendBlock(Connection con, String actorId, String actionType, int recordId, String dataPayload) throws SQLException {
        ensureTableExists(con);

        String previousHash = GENESIS_HASH;
        String getLastHashSql = "SELECT current_hash FROM audit_ledger ORDER BY id DESC LIMIT 1";
        try (Statement st = con.createStatement();
             ResultSet rs = st.executeQuery(getLastHashSql)) {
            if (rs.next()) {
                previousHash = rs.getString("current_hash");
            }
        }

        Timestamp ts = new Timestamp(System.currentTimeMillis());
        
        String insertSql = "INSERT INTO audit_ledger (timestamp, actor_id, action_type, record_id, data_payload, previous_hash, current_hash) VALUES (?, ?, ?, ?, ?, ?, ?)";
        int generatedId = -1;
        try (PreparedStatement ps = con.prepareStatement(insertSql, Statement.RETURN_GENERATED_KEYS)) {
            ps.setTimestamp(1, ts);
            ps.setString(2, actorId != null ? actorId : "SYSTEM");
            ps.setString(3, actionType != null ? actionType : "UNKNOWN");
            ps.setInt(4, recordId);
            ps.setString(5, dataPayload != null ? dataPayload : "");
            ps.setString(6, previousHash);
            ps.setString(7, "TEMP_HASH");
            ps.executeUpdate();

            try (ResultSet keys = ps.getGeneratedKeys()) {
                if (keys.next()) {
                    generatedId = keys.getInt(1);
                }
            }
        }

        if (generatedId == -1) {
            throw new SQLException("Failed to get auto-increment ID for audit ledger entry.");
        }

        // Fetch exact stored timestamp string to guarantee bit-exact hashing alignment
        String fetchSql = "SELECT timestamp FROM audit_ledger WHERE id = ?";
        String timestampStr = ts.toString();
        try (PreparedStatement ps = con.prepareStatement(fetchSql)) {
            ps.setInt(1, generatedId);
            try (ResultSet rs = ps.executeQuery()) {
                if (rs.next()) {
                    Timestamp fetchedTs = rs.getTimestamp("timestamp");
                    if (fetchedTs != null) {
                        ts = fetchedTs;
                        timestampStr = ts.toString();
                    }
                }
            }
        }

        String computedHash = calculateSha256(generatedId, timestampStr, actorId != null ? actorId : "SYSTEM", actionType != null ? actionType : "UNKNOWN", dataPayload != null ? dataPayload : "", previousHash);

        String updateHashSql = "UPDATE audit_ledger SET current_hash = ? WHERE id = ?";
        try (PreparedStatement ps = con.prepareStatement(updateHashSql)) {
            ps.setString(1, computedHash);
            ps.setInt(2, generatedId);
            ps.executeUpdate();
        }

        return new LedgerEntry(generatedId, ts, actorId, actionType, recordId, dataPayload, previousHash, computedHash);
    }

    public static String calculateSha256(int id, String timestamp, String actorId, String actionType, String dataPayload, String previousHash) {
        String rawInput = id + timestamp + actorId + actionType + dataPayload + previousHash;
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hashBytes = digest.digest(rawInput.getBytes(StandardCharsets.UTF_8));
            StringBuilder hexString = new StringBuilder();
            for (byte b : hashBytes) {
                String hex = Integer.toHexString(0xff & b);
                if (hex.length() == 1) hexString.append('0');
                hexString.append(hex);
            }
            return hexString.toString();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("SHA-256 algorithm not available", e);
        }
    }

    public static VerificationResult verifyChain() {
        try (Connection con = DBConnection.getConnection()) {
            if (con == null) {
                return new VerificationResult(false, "DB_ERROR", -1, 0, "Could not connect to database");
            }
            return verifyChain(con);
        } catch (Exception e) {
            return new VerificationResult(false, "ERROR", -1, 0, e.getMessage());
        }
    }

    public static VerificationResult verifyChain(Connection con) throws SQLException {
        ensureTableExists(con);

        List<LedgerEntry> entries = getAllEntries(con);
        int total = entries.size();

        if (total == 0) {
            return new VerificationResult(true, "SECURE", 0, 0, "Audit ledger is empty and uncompromised.");
        }

        String expectedPreviousHash = GENESIS_HASH;

        for (int i = 0; i < total; i++) {
            LedgerEntry entry = entries.get(i);
            int rowId = entry.getId();
            String timestampStr = entry.getTimestamp() != null ? entry.getTimestamp().toString() : "";

            // 1. Verify previous_hash linkage
            if (!entry.getPreviousHash().equals(expectedPreviousHash)) {
                String details = String.format("Broken Hash Linkage at Row ID %d. Expected previous_hash: %s, Found: %s",
                        rowId, expectedPreviousHash, entry.getPreviousHash());
                return new VerificationResult(false, "TAMPER_DETECTED", rowId, total, details);
            }

            // 2. Recompute current_hash for current row payload
            String recomputedHash = calculateSha256(rowId, timestampStr, entry.getActorId(), entry.getActionType(), entry.getDataPayload(), entry.getPreviousHash());

            if (!entry.getCurrentHash().equalsIgnoreCase(recomputedHash)) {
                String details = String.format("Content Tampering Detected at Row ID %d. Stored hash: %s, Recomputed hash: %s",
                        rowId, entry.getCurrentHash(), recomputedHash);
                return new VerificationResult(false, "TAMPER_DETECTED", rowId, total, details);
            }

            // Advance state
            expectedPreviousHash = entry.getCurrentHash();
        }

        return new VerificationResult(true, "SECURE", 0, total, "All " + total + " historical ledger blocks verified intact.");
    }

    public static List<LedgerEntry> getAllEntries() {
        try (Connection con = DBConnection.getConnection()) {
            if (con == null) return new ArrayList<>();
            return getAllEntries(con);
        } catch (Exception e) {
            e.printStackTrace();
            return new ArrayList<>();
        }
    }

    public static List<LedgerEntry> getAllEntries(Connection con) throws SQLException {
        ensureTableExists(con);
        List<LedgerEntry> list = new ArrayList<>();
        String sql = "SELECT * FROM audit_ledger ORDER BY id ASC";
        try (Statement st = con.createStatement();
             ResultSet rs = st.executeQuery(sql)) {
            while (rs.next()) {
                list.add(new LedgerEntry(
                        rs.getInt("id"),
                        rs.getTimestamp("timestamp"),
                        rs.getString("actor_id"),
                        rs.getString("action_type"),
                        rs.getInt("record_id"),
                        rs.getString("data_payload"),
                        rs.getString("previous_hash"),
                        rs.getString("current_hash")
                ));
            }
        }
        return list;
    }
}
