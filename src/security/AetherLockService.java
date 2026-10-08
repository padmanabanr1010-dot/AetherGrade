package security;

import database.DBConnection;
import model.Student;
import repository.StudentRepository;
import audit.AuditLedgerUtil;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.sql.*;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * AetherLock Cryptographic Core Service.
 * Manages Term Seals, Merkle Root issuance, Zero-Knowledge Credential Generation,
 * and Stateless Zero-Trust Verification.
 */
public class AetherLockService {

    public static final String HMAC_SECRET = "AETHERLOCK_CRYPTOGRAPHIC_SEAL_KEY_2026_ZERO_TRUST_VERIFICATION";

    public static class TermSeal {
        private final String sealId;
        private final String termId;
        private final String merkleRoot;
        private final Timestamp lockedAt;
        private final String signature;
        private final boolean isSealed;
        private final int studentCount;
        private final String actorId;
        private final String salt;

        public TermSeal(String sealId, String termId, String merkleRoot, Timestamp lockedAt,
                        String signature, boolean isSealed, int studentCount, String actorId, String salt) {
            this.sealId = sealId;
            this.termId = termId;
            this.merkleRoot = merkleRoot;
            this.lockedAt = lockedAt;
            this.signature = signature;
            this.isSealed = isSealed;
            this.studentCount = studentCount;
            this.actorId = actorId;
            this.salt = salt;
        }

        public String getSealId() { return sealId; }
        public String getTermId() { return termId; }
        public String getMerkleRoot() { return merkleRoot; }
        public Timestamp getLockedAt() { return lockedAt; }
        public String getSignature() { return signature; }
        public boolean isSealed() { return isSealed; }
        public int getStudentCount() { return studentCount; }
        public String getActorId() { return actorId; }
        public String getSalt() { return salt; }

        public String toJson() {
            return String.format(Locale.US,
                "{\"sealId\":\"%s\",\"termId\":\"%s\",\"merkleRoot\":\"%s\",\"lockedAt\":\"%s\",\"signature\":\"%s\",\"isSealed\":%b,\"studentCount\":%d,\"actorId\":\"%s\",\"salt\":\"%s\"}",
                sealId, escapeJson(termId), merkleRoot, lockedAt != null ? lockedAt.toString() : "",
                escapeJson(signature), isSealed, studentCount, escapeJson(actorId), escapeJson(salt)
            );
        }
    }

    public static class SealResponse {
        private final TermSeal seal;
        private final List<List<String>> treeLevels;
        private final List<Map<String, Object>> studentLeaves;

        public SealResponse(TermSeal seal, List<List<String>> treeLevels, List<Map<String, Object>> studentLeaves) {
            this.seal = seal;
            this.treeLevels = treeLevels;
            this.studentLeaves = studentLeaves;
        }

        public TermSeal getSeal() { return seal; }
        public List<List<String>> getTreeLevels() { return treeLevels; }
        public List<Map<String, Object>> getStudentLeaves() { return studentLeaves; }
    }

    public static class VerificationResult {
        private final boolean valid;
        private final int studentId;
        private final String termId;
        private final String merkleRoot;
        private final Map<String, Object> claims;
        private final List<String> auditTrail;
        private final String error;

        public VerificationResult(boolean valid, int studentId, String termId, String merkleRoot,
                                  Map<String, Object> claims, List<String> auditTrail, String error) {
            this.valid = valid;
            this.studentId = studentId;
            this.termId = termId;
            this.merkleRoot = merkleRoot;
            this.claims = claims;
            this.auditTrail = auditTrail;
            this.error = error;
        }

        public boolean isValid() { return valid; }
        public int getStudentId() { return studentId; }
        public String getTermId() { return termId; }
        public String getMerkleRoot() { return merkleRoot; }
        public Map<String, Object> getClaims() { return claims; }
        public List<String> getAuditTrail() { return auditTrail; }
        public String getError() { return error; }

        public String toJson() {
            StringBuilder trailJson = new StringBuilder("[");
            for (int i = 0; i < auditTrail.size(); i++) {
                trailJson.append("\"").append(escapeJson(auditTrail.get(i))).append("\"");
                if (i < auditTrail.size() - 1) trailJson.append(",");
            }
            trailJson.append("]");

            StringBuilder claimsJson = new StringBuilder("{");
            if (claims != null) {
                int count = 0;
                for (Map.Entry<String, Object> entry : claims.entrySet()) {
                    if (count > 0) claimsJson.append(",");
                    claimsJson.append("\"").append(escapeJson(entry.getKey())).append("\":");
                    if (entry.getValue() instanceof Boolean || entry.getValue() instanceof Number) {
                        claimsJson.append(entry.getValue());
                    } else {
                        claimsJson.append("\"").append(escapeJson(String.valueOf(entry.getValue()))).append("\"");
                    }
                    count++;
                }
            }
            claimsJson.append("}");

            return String.format(Locale.US,
                "{\"valid\":%b,\"studentId\":%d,\"termId\":\"%s\",\"merkleRoot\":\"%s\",\"claims\":%s,\"auditTrail\":%s,\"error\":%s}",
                valid, studentId, escapeJson(termId != null ? termId : ""),
                escapeJson(merkleRoot != null ? merkleRoot : ""),
                claimsJson.toString(),
                trailJson.toString(),
                error != null ? "\"" + escapeJson(error) + "\"" : "null"
            );
        }
    }

    public static void ensureTableExists(Connection con) {
        if (con == null) return;
        try (Statement st = con.createStatement()) {
            st.executeUpdate(
                "CREATE TABLE IF NOT EXISTS term_seals (" +
                "seal_id VARCHAR(36) PRIMARY KEY, " +
                "term_id VARCHAR(50) NOT NULL, " +
                "merkle_root VARCHAR(64) NOT NULL, " +
                "locked_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, " +
                "signature TEXT NOT NULL, " +
                "is_sealed BOOLEAN NOT NULL DEFAULT TRUE, " +
                "student_count INT NOT NULL DEFAULT 0, " +
                "actor_id VARCHAR(50) NOT NULL, " +
                "salt VARCHAR(64) NOT NULL" +
                ")"
            );
        } catch (SQLException ignored) {}
    }

    private static volatile boolean immutabilityEnforced = true;

    public static void setImmutabilityEnforced(boolean enforced) {
        immutabilityEnforced = enforced;
    }

    public static boolean isImmutabilityEnforced() {
        return immutabilityEnforced;
    }

    /**
     * Checks if any active term seal is currently locking records in the database.
     */
    public static boolean isSystemSealed() {
        if (!immutabilityEnforced) return false;
        try (Connection con = DBConnection.getConnection()) {
            if (con == null) return false;
            ensureTableExists(con);
            try (Statement st = con.createStatement();
                 ResultSet rs = st.executeQuery("SELECT COUNT(*) FROM term_seals WHERE is_sealed = TRUE")) {
                if (rs.next()) {
                    return rs.getInt(1) > 0;
                }
            }
        } catch (Exception e) {
            System.err.println("Notice checking system seal status: " + e.getMessage());
        }
        return false;
    }

    public static void clearAllSealsForTesting() {
        try (Connection con = DBConnection.getConnection()) {
            if (con != null) {
                ensureTableExists(con);
                try (Statement st = con.createStatement()) {
                    st.executeUpdate("DELETE FROM term_seals");
                }
            }
        } catch (Exception ignored) {}
    }

    /**
     * Checks if a specific term or student record is locked.
     */
    public static boolean isStudentLocked(int studentId) {
        return isSystemSealed();
    }

    /**
     * Retrieves all term seals in reverse chronological order.
     */
    public static List<TermSeal> getAllSeals() {
        List<TermSeal> seals = new ArrayList<>();
        try (Connection con = DBConnection.getConnection()) {
            if (con == null) return seals;
            ensureTableExists(con);
            String sql = "SELECT * FROM term_seals ORDER BY locked_at DESC";
            try (PreparedStatement ps = con.prepareStatement(sql);
                 ResultSet rs = ps.executeQuery()) {
                while (rs.next()) {
                    seals.add(new TermSeal(
                        rs.getString("seal_id"),
                        rs.getString("term_id"),
                        rs.getString("merkle_root"),
                        rs.getTimestamp("locked_at"),
                        rs.getString("signature"),
                        rs.getBoolean("is_sealed"),
                        rs.getInt("student_count"),
                        rs.getString("actor_id"),
                        rs.getString("salt")
                    ));
                }
            }
        } catch (Exception e) {
            System.err.println("Error fetching term seals: " + e.getMessage());
        }
        return seals;
    }

    public static TermSeal getLatestSeal() {
        List<TermSeal> seals = getAllSeals();
        return seals.isEmpty() ? null : seals.get(0);
    }

    /**
     * Seals an academic term, generating a Merkle Tree over all student records,
     * signing the root, persisting the seal to MySQL, and logging to the immutable audit ledger.
     */
    public static SealResponse sealTerm(String termId, String actorId, StudentRepository repository) throws Exception {
        if (termId == null || termId.trim().isEmpty()) {
            termId = "SPRING-2026";
        }
        termId = termId.trim().toUpperCase();

        List<Student> students = repository.getAllStudents();
        if (students.isEmpty()) {
            throw new IllegalStateException("Cannot seal term: No student records found in the database.");
        }

        String sealId = UUID.randomUUID().toString();
        String salt = UUID.randomUUID().toString().replace("-", "").substring(0, 16);

        MerkleTree tree = new MerkleTree(termId, salt, students);
        String rootHash = tree.getRootHash();

        // Generate institutional HMAC signature over root and metadata
        String signature = signHmac(sealId + ":" + termId + ":" + rootHash + ":" + salt);

        Timestamp now = new Timestamp(System.currentTimeMillis());
        TermSeal seal = new TermSeal(sealId, termId, rootHash, now, signature, true, students.size(), actorId, salt);

        // Store into MySQL
        try (Connection con = DBConnection.getConnection()) {
            if (con != null) {
                ensureTableExists(con);
                String sql = "INSERT INTO term_seals (seal_id, term_id, merkle_root, locked_at, signature, is_sealed, student_count, actor_id, salt) " +
                             "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)";
                try (PreparedStatement ps = con.prepareStatement(sql)) {
                    ps.setString(1, sealId);
                    ps.setString(2, termId);
                    ps.setString(3, rootHash);
                    ps.setTimestamp(4, now);
                    ps.setString(5, signature);
                    ps.setBoolean(6, true);
                    ps.setInt(7, students.size());
                    ps.setString(8, actorId);
                    ps.setString(9, salt);
                    ps.executeUpdate();
                }

                // Append block to immutable audit ledger
                AuditLedgerUtil.appendBlock(con, actorId, "AETHERLOCK_TERM_SEAL", 0,
                    String.format(Locale.US, "Term '%s' cryptographically sealed. Merkle Root: %s. Seal ID: %s. Records locked: %d",
                        termId, rootHash, sealId, students.size())
                );
            }
        }

        // Prepare leaf summaries for frontend cascade animation
        List<Map<String, Object>> leavesInfo = new ArrayList<>();
        for (MerkleTree.Leaf leaf : tree.getLeaves()) {
            Map<String, Object> m = new HashMap<>();
            m.put("studentId", leaf.getStudentId());
            m.put("department", leaf.getDepartment());
            m.put("grade", leaf.getGrade());
            m.put("totalMarks", leaf.getTotalMarks());
            m.put("leafHash", leaf.getLeafHash());
            leavesInfo.add(m);
        }

        return new SealResponse(seal, tree.getTreeLevels(), leavesInfo);
    }

    /**
     * Generates a Zero-Knowledge privacy credential token asserting student criteria
     * with an accompanying Merkle proof path without exposing individual subject scores.
     */
    public static String generateZkCredential(int studentId, StudentRepository repository) throws Exception {
        Student student = repository.getStudent(studentId);
        List<Student> allStudents = repository.getAllStudents();

        TermSeal seal = getLatestSeal();
        String salt;
        String termId;
        String expectedRoot;

        if (seal != null) {
            salt = seal.getSalt();
            termId = seal.getTermId();
            expectedRoot = seal.getMerkleRoot();
        } else {
            // Ephemeral active term seal if not yet sealed
            salt = "DEFAULT_SALT_" + studentId;
            termId = "ACTIVE-TERM-2026";
            MerkleTree tempTree = new MerkleTree(termId, salt, allStudents);
            expectedRoot = tempTree.getRootHash();
        }

        MerkleTree tree = new MerkleTree(termId, salt, allStudents);
        List<MerkleTree.ProofStep> proof = tree.getProof(studentId);
        String leafHash = MerkleTree.Leaf.computeLeafHash(
            student.getStudentId(), student.getDepartment(), student.getGrade(), student.getTotal(), salt
        );

        // Derive privacy-preserving claims (omits raw subject marks)
        double pct = student.getPercentage();
        String gpaBracket;
        if (pct >= 90.0) gpaBracket = "FIRST_CLASS_DISTINCTION";
        else if (pct >= 75.0) gpaBracket = "FIRST_CLASS_HONORS";
        else if (pct >= 60.0) gpaBracket = "SECOND_CLASS_UPPER";
        else if (pct >= 50.0) gpaBracket = "SECOND_CLASS_LOWER";
        else gpaBracket = "UNSATISFACTORY";

        boolean hasPassedAll = pct >= 50.0 && !"FAIL".equalsIgnoreCase(student.getGrade());
        boolean isEligibleForExam = student.getAttendance() >= 75.0;
        String status = pct >= 80.0 ? "Graduated with Honors" : (hasPassedAll ? "Satisfactory Academic Standing" : "Academic Probation");

        long issuedAt = System.currentTimeMillis();
        long expiresAt = issuedAt + (365L * 24 * 60 * 60 * 1000L); // 1 Year validity
        String tokenId = "ZK-" + UUID.randomUUID().toString().substring(0, 8).toUpperCase();

        StringBuilder proofJson = new StringBuilder("[");
        for (int i = 0; i < proof.size(); i++) {
            proofJson.append(proof.get(i).toJson());
            if (i < proof.size() - 1) proofJson.append(",");
        }
        proofJson.append("]");

        String claimsPayload = String.format(Locale.US,
            "{\"gpaBracket\":\"%s\",\"hasPassedAll\":%b,\"isEligibleForExam\":%b,\"status\":\"%s\",\"department\":\"%s\"}",
            gpaBracket, hasPassedAll, isEligibleForExam, status, escapeJson(student.getDepartment())
        );

        String credentialBody = String.format(Locale.US,
            "{\"tokenId\":\"%s\",\"studentId\":%d,\"termId\":\"%s\",\"merkleRoot\":\"%s\",\"leafHash\":\"%s\",\"merkleProof\":%s,\"claims\":%s,\"salt\":\"%s\",\"issuedAt\":%d,\"expiresAt\":%d}",
            tokenId, studentId, termId, expectedRoot, leafHash, proofJson.toString(), claimsPayload, salt, issuedAt, expiresAt
        );

        String signature = signHmac(credentialBody);
        String finalBundle = String.format(Locale.US, "{\"payload\":%s,\"signature\":\"%s\"}", credentialBody, signature);

        return Base64.getUrlEncoder().withoutPadding().encodeToString(finalBundle.getBytes(StandardCharsets.UTF_8));
    }

    /**
     * Stateless verification of a lightweight Zero-Knowledge credential payload or QR token.
     * Validates leaf reconstruction, Merkle tree membership proof, and institution signature
     * without requiring direct database access.
     */
    public static VerificationResult verifyProof(String rawInput) {
        List<String> auditTrail = new ArrayList<>();
        auditTrail.add("Step 1: Input decoded into JSON cryptographic bundle");

        if (rawInput == null || rawInput.trim().isEmpty()) {
            return new VerificationResult(false, 0, null, null, null, auditTrail, "Empty verification token provided.");
        }

        String jsonString = rawInput.trim();
        // Check if Base64URL encoded
        if (!jsonString.startsWith("{") && !jsonString.startsWith("[")) {
            try {
                byte[] decoded = Base64.getUrlDecoder().decode(jsonString);
                jsonString = new String(decoded, StandardCharsets.UTF_8);
                auditTrail.add("Step 1b: Base64URL envelope successfully decoded");
            } catch (Exception e) {
                try {
                    byte[] decoded = Base64.getDecoder().decode(jsonString);
                    jsonString = new String(decoded, StandardCharsets.UTF_8);
                    auditTrail.add("Step 1b: Base64 standard envelope successfully decoded");
                } catch (Exception ignored) {
                    return new VerificationResult(false, 0, null, null, null, auditTrail, "Malformed token: Not valid Base64 or JSON.");
                }
            }
        }

        try {
            // Ensure jsonString is a single valid JSON object without trailing extraneous content
            int firstBrace = jsonString.indexOf('{');
            int lastBrace = jsonString.lastIndexOf('}');
            if (firstBrace == -1 || lastBrace == -1 || firstBrace >= lastBrace) {
                auditTrail.add("Step 1c: ❌ Malformed JSON object boundaries");
                return new VerificationResult(false, 0, null, null, null, auditTrail, "Malformed JSON object boundaries in token.");
            }

            String trailing = jsonString.substring(lastBrace + 1).trim();
            if (!trailing.isEmpty()) {
                auditTrail.add("Step 1c: ❌ Trailing extraneous bytes detected after payload envelope");
                return new VerificationResult(false, 0, null, null, null, auditTrail, "Malformed token: Extraneous bytes detected after envelope.");
            }

            // Parse outer payload and signature
            String payloadJson = extractJsonField(jsonString, "payload");
            String signature = extractJsonString(jsonString, "signature");

            if (payloadJson == null || payloadJson.isEmpty()) {
                // Try if raw input is the payload directly
                payloadJson = jsonString;
            }

            // Step 2: Verify cryptographic institution signature
            if (signature == null || signature.trim().isEmpty()) {
                auditTrail.add("Step 2: ❌ Institutional HMAC signature missing from credential bundle");
                return new VerificationResult(false, 0, null, null, null, auditTrail, "Missing institutional signature in credential bundle.");
            }

            String expectedSig = signHmac(payloadJson);
            if (!expectedSig.equals(signature)) {
                auditTrail.add("Step 2: ❌ Institutional HMAC signature check failed (Potential forgery)");
                return new VerificationResult(false, 0, null, null, null, auditTrail, "Cryptographic signature mismatch: Token has been tampered with or forged.");
            }
            auditTrail.add("Step 2: ✅ Institutional HMAC signature verified authentic");

            // Extract payload properties
            int studentId = extractJsonInt(payloadJson, "studentId");
            String termId = extractJsonString(payloadJson, "termId");
            String merkleRoot = extractJsonString(payloadJson, "merkleRoot");
            String leafHash = extractJsonString(payloadJson, "leafHash");
            long expiresAt = extractJsonLong(payloadJson, "expiresAt");

            if (studentId <= 0 || leafHash.trim().isEmpty() || merkleRoot.trim().isEmpty() || merkleRoot.length() != 64) {
                auditTrail.add("Step 3: ❌ Malformed leaf hash or Merkle root parameter");
                return new VerificationResult(false, studentId, termId, merkleRoot, null, auditTrail, "Malformed cryptographic parameters in credential.");
            }

            if (expiresAt > 0 && System.currentTimeMillis() > expiresAt) {
                auditTrail.add("Step 3: ❌ Credential token has expired");
                return new VerificationResult(false, studentId, termId, merkleRoot, null, auditTrail, "Credential token expired on " + new java.util.Date(expiresAt));
            }
            auditTrail.add("Step 3: ✅ Token validity period verified (Unexpired)");

            // Extract claims
            Map<String, Object> claims = new HashMap<>();
            String claimsSub = extractJsonField(payloadJson, "claims");
            if (claimsSub != null) {
                claims.put("gpaBracket", extractJsonString(claimsSub, "gpaBracket"));
                claims.put("hasPassedAll", extractJsonBoolean(claimsSub, "hasPassedAll"));
                claims.put("isEligibleForExam", extractJsonBoolean(claimsSub, "isEligibleForExam"));
                claims.put("status", extractJsonString(claimsSub, "status"));
                claims.put("department", extractJsonString(claimsSub, "department"));
            }

            // Extract Merkle proof steps
            List<MerkleTree.ProofStep> proofSteps = parseMerkleProof(payloadJson);
            auditTrail.add("Step 4: Parsed " + proofSteps.size() + " cryptographic sibling proof steps in Merkle audit path");

            // Step 5: Stateless proof path verification
            boolean proofValid = MerkleTree.verifyProof(leafHash, proofSteps, merkleRoot);
            if (!proofValid) {
                auditTrail.add("Step 5: ❌ Merkle root recalculation mismatch (Computed root != Expected root)");
                return new VerificationResult(false, studentId, termId, merkleRoot, claims, auditTrail, "Merkle Tree Proof Verification Failed: Leaf does not belong to root " + merkleRoot);
            }
            auditTrail.add("Step 5: ✅ Merkle proof verified: Calculated hash path strictly terminates at root " + merkleRoot);

            auditTrail.add("Step 6: ✅ Zero-Trust Verification 100% Successful. Criteria proven without leaking raw grades.");

            return new VerificationResult(true, studentId, termId, merkleRoot, claims, auditTrail, null);

        } catch (Exception e) {
            auditTrail.add("Verification error: " + e.getMessage());
            return new VerificationResult(false, 0, null, null, null, auditTrail, "Error processing proof: " + e.getMessage());
        }
    }

    private static List<MerkleTree.ProofStep> parseMerkleProof(String json) {
        List<MerkleTree.ProofStep> steps = new ArrayList<>();
        Pattern p = Pattern.compile("\\{\\s*\"position\"\\s*:\\s*\"([^\"]+)\"\\s*,\\s*\"hash\"\\s*:\\s*\"([^\"]+)\"\\s*\\}");
        Matcher m = p.matcher(json);
        while (m.find()) {
            steps.add(new MerkleTree.ProofStep(m.group(1), m.group(2)));
        }
        return steps;
    }

    public static String signHmac(String data) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            SecretKeySpec secretKey = new SecretKeySpec(HMAC_SECRET.getBytes(StandardCharsets.UTF_8), "HmacSHA256");
            mac.init(secretKey);
            byte[] hmac = mac.doFinal(data.getBytes(StandardCharsets.UTF_8));
            StringBuilder sb = new StringBuilder();
            for (byte b : hmac) {
                sb.append(String.format("%02x", b));
            }
            return sb.toString();
        } catch (Exception e) {
            throw new RuntimeException("HMAC computation failed", e);
        }
    }

    private static String escapeJson(String s) {
        if (s == null) return "";
        return s.replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", " ").replace("\r", "");
    }

    private static String extractJsonString(String json, String key) {
        Pattern p = Pattern.compile("\"" + key + "\"\\s*:\\s*\"([^\"]*)\"");
        Matcher m = p.matcher(json);
        return m.find() ? m.group(1) : "";
    }

    private static int extractJsonInt(String json, String key) {
        Pattern p = Pattern.compile("\"" + key + "\"\\s*:\\s*\"?(-?\\d+)\"?");
        Matcher m = p.matcher(json);
        return m.find() ? Integer.parseInt(m.group(1)) : 0;
    }

    private static long extractJsonLong(String json, String key) {
        Pattern p = Pattern.compile("\"" + key + "\"\\s*:\\s*\"?(\\d+)\"?");
        Matcher m = p.matcher(json);
        return m.find() ? Long.parseLong(m.group(1)) : 0L;
    }

    private static boolean extractJsonBoolean(String json, String key) {
        Pattern p = Pattern.compile("\"" + key + "\"\\s*:\\s*(true|false)");
        Matcher m = p.matcher(json);
        return m.find() && Boolean.parseBoolean(m.group(1));
    }

    private static String extractJsonField(String json, String key) {
        int idx = json.indexOf("\"" + key + "\"");
        if (idx == -1) return null;
        int colon = json.indexOf(":", idx);
        if (colon == -1) return null;
        int start = colon + 1;
        while (start < json.length() && Character.isWhitespace(json.charAt(start))) start++;
        if (start >= json.length()) return null;

        char first = json.charAt(start);
        if (first == '{' || first == '[') {
            char endChar = (first == '{') ? '}' : ']';
            int depth = 0;
            for (int i = start; i < json.length(); i++) {
                char c = json.charAt(i);
                if (c == first) depth++;
                else if (c == endChar) depth--;
                if (depth == 0) {
                    return json.substring(start, i + 1);
                }
            }
        }
        return null;
    }
}
