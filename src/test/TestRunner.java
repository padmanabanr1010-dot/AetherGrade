package test;

import model.Student;
import model.AcademicStudent;
import security.PasswordHasher;
import security.CryptoUtil;
import security.JwtUtil;
import security.RateLimiter;
import security.ZkpVerificationUtil;
import security.MerkleTree;
import security.AetherLockService;
import repository.JdbcStudentRepository;
import repository.StudentRepository;
import audit.AuditLedgerUtil;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.util.*;
import database.DBConnection;

public class TestRunner {

    private static int passedCount = 0;
    private static int failedCount = 0;

    public static void main(String[] args) {
        System.out.println("=================================================");
        System.out.println("  RUNNING STUDENT GRADE MANAGER UNIT TEST SUITE  ");
        System.out.println("=================================================");

        testStudentGradeCalculation();
        testAcademicStudentExamEligibility();
        testPasswordHasher();
        testCryptoUtilAESGCM();
        testJwtGenerationAndValidation();
        testRateLimiter();
        testAuditLedgerHashChainAndTamperDetection();
        testZkpTokenGenerationAndTamperDetection();
        testAetherLockMerkleTreeConstructionAndProof();
        testAetherLockCredentialGenerationAndZeroTrustVerification();
        testAetherLockTermSealingAndImmutability();

        System.out.println("\n-------------------------------------------------");
        System.out.println(String.format("TEST RESULTS: %d PASSED, %d FAILED", passedCount, failedCount));
        System.out.println("-------------------------------------------------");

        if (failedCount > 0) {
            System.exit(1);
        }
    }

    private static void assertEquals(Object expected, Object actual, String testName) {
        if ((expected == null && actual == null) || (expected != null && expected.equals(actual))) {
            System.out.println("[PASS] " + testName);
            passedCount++;
        } else {
            System.err.println("[FAIL] " + testName + " - Expected: " + expected + ", Got: " + actual);
            failedCount++;
        }
    }

    private static void assertTrue(boolean condition, String testName) {
        if (condition) {
            System.out.println("[PASS] " + testName);
            passedCount++;
        } else {
            System.err.println("[FAIL] " + testName + " - Expected true but got false");
            failedCount++;
        }
    }

    private static void testStudentGradeCalculation() {
        System.out.println("\n--- Testing Student Grade Calculations ---");
        // Marks: Java=95, OS=90, Maths=92, DAA=88, CA=94, ML=91 -> Total = 550, Percentage = 91.67 -> Grade O
        Student s1 = new Student(101, "Alice", "CSE", 3, 95, 90, 92, 88, 94, 91, 85.0);
        assertEquals(550, s1.getTotal(), "Student Total Marks Calculation");
        assertEquals("O", s1.getGrade(), "Student Grade 'O' Threshold Calculation (>=90%)");

        // Fail test: 40 across all subjects -> Total = 240, Percentage = 40.0 -> Grade FAIL
        Student s2 = new Student(102, "Bob", "ECE", 2, 40, 40, 40, 40, 40, 40, 60.0);
        assertEquals("FAIL", s2.getGrade(), "Student Grade 'FAIL' Threshold Calculation (<50%)");
    }

    private static void testAcademicStudentExamEligibility() {
        System.out.println("\n--- Testing Academic Student Exam Eligibility ---");
        AcademicStudent eligibleStudent = new AcademicStudent(103, "Charlie", "EEE", 4, 80, 80, 80, 80, 80, 80, 78.5);
        assertTrue(eligibleStudent.isEligibleForExam(), "Student with 78.5% attendance is eligible for exam");

        AcademicStudent ineligibleStudent = new AcademicStudent(104, "David", "MECH", 1, 70, 70, 70, 70, 70, 70, 72.0);
        assertTrue(!ineligibleStudent.isEligibleForExam(), "Student with 72.0% attendance (<75%) is NOT eligible for exam");
    }

    private static void testPasswordHasher() {
        System.out.println("\n--- Testing BCrypt/PBKDF2 Password Hasher ---");
        String plain = "SecretPassword123!";
        String hash = PasswordHasher.hashPassword(plain);
        
        assertTrue(hash.startsWith("PBKDF2$"), "Password hash format starts with PBKDF2$");
        assertTrue(PasswordHasher.verifyPassword(plain, hash), "PasswordHasher verifies correct password");
        assertTrue(!PasswordHasher.verifyPassword("WrongPassword", hash), "PasswordHasher rejects wrong password");
    }

    private static void testCryptoUtilAESGCM() {
        System.out.println("\n--- Testing AES-256-GCM Encryption ---");
        String secretData = "student101@university.edu";
        String encrypted = CryptoUtil.encrypt(secretData);
        
        assertTrue(!secretData.equals(encrypted), "Encrypted text is different from plaintext");
        String decrypted = CryptoUtil.decrypt(encrypted);
        assertEquals(secretData, decrypted, "Decrypted text matches original plaintext");
    }

    private static void testJwtGenerationAndValidation() {
        System.out.println("\n--- Testing JWT Token Generation & Validation ---");
        String token = JwtUtil.generateToken("faculty_user", "FACULTY", null);
        assertTrue(token != null && token.contains("."), "Generated valid JWT token string format");

        JwtUtil.UserClaims claims = JwtUtil.validateToken(token);
        assertTrue(claims != null, "JWT token validation succeeded");
        assertEquals("faculty_user", claims.getUsername(), "JWT payload contains correct username");
        assertEquals("FACULTY", claims.getRole(), "JWT payload contains correct role");

        JwtUtil.UserClaims invalidClaims = JwtUtil.validateToken(token + "tampered");
        assertTrue(invalidClaims == null, "Tampered JWT token signature is rejected");
    }

    private static void testRateLimiter() {
        System.out.println("\n--- Testing Token Bucket Rate Limiter ---");
        String testIp = "192.168.1.100_TEST";
        // Allow up to 2 requests
        assertTrue(RateLimiter.allowRequest(testIp, 2, 60000), "First request within limit allowed");
        assertTrue(RateLimiter.allowRequest(testIp, 2, 60000), "Second request within limit allowed");
        assertTrue(!RateLimiter.allowRequest(testIp, 2, 60000), "Third request exceeding capacity blocked");
    }

    private static void testAuditLedgerHashChainAndTamperDetection() {
        System.out.println("\n--- Testing Tamper-Evident Immutable Audit Ledger ---");
        AuditLedgerUtil.LedgerEntry entry1 = AuditLedgerUtil.appendBlock("TEST_ACTOR", "GRADE_UPDATE", 101, "Java=95, OS=90, Maths=92");
        AuditLedgerUtil.LedgerEntry entry2 = AuditLedgerUtil.appendBlock("TEST_ACTOR", "ATTENDANCE_CHANGE", 101, "Attendance=88.5%");
        
        assertTrue(entry1 != null && entry1.getCurrentHash() != null, "Successfully appended block #1 to audit ledger");
        assertTrue(entry2 != null && entry2.getPreviousHash().equals(entry1.getCurrentHash()), "Block #2 previous_hash correctly links to block #1 current_hash");

        AuditLedgerUtil.VerificationResult intactResult = AuditLedgerUtil.verifyChain();
        assertTrue(intactResult.isValid(), "Audit Ledger sequence verification succeeds on intact database");

        // Simulate single-byte out-of-band database tampering
        int tamperedRowId = entry1.getId();
        String originalPayload = entry1.getDataPayload();
        try (Connection con = DBConnection.getConnection();
             PreparedStatement ps = con.prepareStatement("UPDATE audit_ledger SET data_payload = ? WHERE id = ?")) {
            ps.setString(1, originalPayload + "_TAMPERED");
            ps.setInt(2, tamperedRowId);
            ps.executeUpdate();

            AuditLedgerUtil.VerificationResult tamperResult = AuditLedgerUtil.verifyChain();
            assertTrue(!tamperResult.isValid(), "Audit Ledger engine detects historical single-byte tampering");
            assertEquals("TAMPER_DETECTED", tamperResult.getStatus(), "Verification status returns TAMPER_DETECTED");
            assertEquals(tamperedRowId, tamperResult.getBrokenRowId(), "Verification engine pinpoints exact tampered row ID #" + tamperedRowId);

            // Revert tampering
            ps.setString(1, originalPayload);
            ps.setInt(2, tamperedRowId);
            ps.executeUpdate();
            
            // Fix hash for test cleanup
            String fixedHash = AuditLedgerUtil.calculateSha256(tamperedRowId, entry1.getTimestamp().toString(), entry1.getActorId(), entry1.getActionType(), originalPayload, entry1.getPreviousHash());
            try (PreparedStatement psFix = con.prepareStatement("UPDATE audit_ledger SET current_hash = ? WHERE id = ?")) {
                psFix.setString(1, fixedHash);
                psFix.setInt(2, tamperedRowId);
                psFix.executeUpdate();
            }
        } catch (Exception e) {
            System.err.println("Audit ledger tamper test warning: " + e.getMessage());
        }
    }

    private static void testZkpTokenGenerationAndTamperDetection() {
        System.out.println("\n--- Testing ZKP-Style Privacy Verification Tokens ---");
        Student testStudent = new AcademicStudent(501, "SecurityTester", "Cyber Security", 3, 90, 85, 92, 88, 94, 91, 82.5);

        String token = ZkpVerificationUtil.generateToken(testStudent);
        assertTrue(token != null && token.contains("."), "Generated Base64URL signed ZKP token format <payload>.<signature>");

        ZkpVerificationUtil.ClaimVerificationResult result = ZkpVerificationUtil.verifyClaim(token);
        assertTrue(result.isValid(), "HMAC-SHA256 token verification succeeded for valid token");
        assertTrue(result.getClaims() != null, "Token payload claims extracted successfully");
        assertTrue(result.getClaims().isEligibleForExam(), "ZKP claim asserts exam eligibility (Attendance 82.5% >= 75%)");
        assertTrue(result.getClaims().isHasPassedAll(), "ZKP claim asserts pass status for all subjects");
        assertEquals("ABOVE_3.5", result.getClaims().getGpaBracket(), "ZKP claim asserts GPA bracket ABOVE_3.5");

        // Test 1: Forged Signature Detection
        String forgedToken = token + "X";
        ZkpVerificationUtil.ClaimVerificationResult forgedResult = ZkpVerificationUtil.verifyClaim(forgedToken);
        assertTrue(!forgedResult.isValid(), "Forged token signature is rejected by ZkpVerificationUtil");

        // Test 2: Expired Token Detection
        String expiredToken = ZkpVerificationUtil.generateToken(testStudent, -5000L); // Expired 5 seconds ago
        ZkpVerificationUtil.ClaimVerificationResult expiredResult = ZkpVerificationUtil.verifyClaim(expiredToken);
        assertTrue(!expiredResult.isValid(), "Expired token is rejected by ZkpVerificationUtil");
    }

    private static void testAetherLockMerkleTreeConstructionAndProof() {
        System.out.println("\n--- Testing AetherLock Merkle Tree & Audit Paths ---");
        List<Student> mockRoster = new ArrayList<>();
        mockRoster.add(new Student(101, "Alice", "CSE", 3, 90, 85, 92, 88, 94, 91, 88.0));
        mockRoster.add(new Student(102, "Bob", "ECE", 3, 75, 70, 72, 68, 74, 71, 76.0));
        mockRoster.add(new Student(103, "Charlie", "EEE", 3, 85, 80, 82, 78, 84, 81, 80.0));
        mockRoster.add(new Student(104, "Diana", "MECH", 3, 60, 65, 62, 58, 64, 61, 72.0));
        mockRoster.add(new Student(105, "Evan", "CIVIL", 3, 95, 92, 96, 94, 98, 93, 90.0)); // Odd number of leaves test

        String salt = "TEST_SALT_2026_SEAL";
        MerkleTree tree = new MerkleTree("FALL-2026", salt, mockRoster);
        String rootHash = tree.getRootHash();

        assertTrue(rootHash != null && rootHash.length() == 64, "Generated 64-character SHA-256 Merkle root hash: " + rootHash);
        assertEquals(5, tree.getLeaves().size(), "Merkle tree constructed with exactly 5 student leaves");

        // Test Merkle Audit Path generation for student #103
        List<MerkleTree.ProofStep> proof = tree.getProof(103);
        assertTrue(!proof.isEmpty(), "Generated non-empty Merkle audit proof path for Student #103");

        String leafHash103 = MerkleTree.Leaf.computeLeafHash(103, "EEE", mockRoster.get(2).getGrade(), mockRoster.get(2).getTotal(), salt);
        boolean verified = MerkleTree.verifyProof(leafHash103, proof, rootHash);
        assertTrue(verified, "Merkle proof path mathematically terminates at the identical root hash");

        // Test Tamper detection on Merkle proof
        boolean tamperedLeafCheck = MerkleTree.verifyProof(leafHash103 + "TAMPERED", proof, rootHash);
        assertTrue(!tamperedLeafCheck, "Tampered leaf hash fails Merkle proof verification");
    }

    private static void testAetherLockCredentialGenerationAndZeroTrustVerification() {
        System.out.println("\n--- Testing AetherLock Zero-Trust Credential & Proof Verifier ---");
        StudentRepository repo = new JdbcStudentRepository();
        try {
            List<Student> students = repo.getAllStudents();
            if (students.isEmpty()) {
                System.out.println("[SKIP] No students in DB for credential test");
                return;
            }

            int testStudentId = students.get(0).getStudentId();
            String credentialToken = AetherLockService.generateZkCredential(testStudentId, repo);

            assertTrue(credentialToken != null && !credentialToken.isEmpty(), "Generated Base64URL AetherLock ZK credential token");

            // Stateless zero-trust verification test
            AetherLockService.VerificationResult result = AetherLockService.verifyProof(credentialToken);
            assertTrue(result.isValid(), "Stateless verification of AetherLock ZK credential succeeded");
            assertEquals(testStudentId, result.getStudentId(), "Credential correctly asserts Student ID #" + testStudentId);
            assertTrue(result.getClaims() != null, "Extracted privacy claims from credential");
            assertTrue(result.getAuditTrail().size() >= 5, "Audit checklist contains all 5+ cryptographic verification stages");

            // Forgery and Tamper Detection
            String forgedToken = credentialToken + "MALICIOUS";
            AetherLockService.VerificationResult forgedResult = AetherLockService.verifyProof(forgedToken);
            assertTrue(!forgedResult.isValid(), "Tampered / forged credential token rejected by Zero-Trust verifier");

        } catch (Exception e) {
            System.err.println("AetherLock credential test exception: " + e.getMessage());
            e.printStackTrace();
            failedCount++;
        }
    }

    private static void testAetherLockTermSealingAndImmutability() {
        System.out.println("\n--- Testing AetherLock Term Sealing & Immutability Enforcement ---");
        StudentRepository repo = new JdbcStudentRepository();
        try {
            List<Student> students = repo.getAllStudents();
            if (students.isEmpty()) {
                System.out.println("[SKIP] No students in DB for term sealing test");
                return;
            }

            String testTerm = "AUTUMN-TEST-" + System.currentTimeMillis();
            AetherLockService.SealResponse sealResp = AetherLockService.sealTerm(testTerm, "ADMIN_TEST", repo);
            AetherLockService.TermSeal seal = sealResp.getSeal();

            assertTrue(seal != null, "Successfully sealed academic term with AetherLock");
            assertEquals(testTerm, seal.getTermId(), "Term seal records correct term ID");
            assertTrue(seal.getMerkleRoot() != null && seal.getMerkleRoot().length() == 64, "Term seal contains authentic 64-char Merkle root");
            assertTrue(seal.isSealed(), "Term seal status is is_sealed = true");

            // Test Immutability Enforcement: Modifying student when term is sealed must be BLOCKED
            Student s = students.get(0);
            boolean threwSecurityException = false;
            try {
                repo.updateStudentMarks(s.getStudentId(), 99, 99, 99, 99, 99, 99);
            } catch (SecurityException se) {
                threwSecurityException = true;
                System.out.println("[PASS] Database mutation rejected as expected: " + se.getMessage());
                passedCount++;
            }

            if (!threwSecurityException) {
                System.err.println("[FAIL] Expected SecurityException when attempting to update sealed student record");
                failedCount++;
            }

            // Cleanup test seal so normal DB operations resume
            AetherLockService.clearAllSealsForTesting();
            assertTrue(!AetherLockService.isSystemSealed(), "Successfully cleared test seal; system unlocked");

        } catch (Exception e) {
            System.err.println("AetherLock term sealing test exception: " + e.getMessage());
            e.printStackTrace();
            failedCount++;
        }
    }
}

