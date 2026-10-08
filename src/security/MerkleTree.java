package security;

import model.Student;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.*;

/**
 * AetherLock Merkle Tree Generator.
 * Constructs a binary Merkle tree over a student roster for a given academic term.
 * Produces cryptographic root seals and audit paths (Merkle proofs) for individual students.
 */
public class MerkleTree {

    public static class Leaf {
        private final int studentId;
        private final String department;
        private final String grade;
        private final int totalMarks;
        private final double attendance;
        private final String leafHash;

        public Leaf(int studentId, String department, String grade, int totalMarks, double attendance, String salt) {
            this.studentId = studentId;
            this.department = department;
            this.grade = grade;
            this.totalMarks = totalMarks;
            this.attendance = attendance;
            this.leafHash = computeLeafHash(studentId, department, grade, totalMarks, salt);
        }

        public int getStudentId() { return studentId; }
        public String getDepartment() { return department; }
        public String getGrade() { return grade; }
        public int getTotalMarks() { return totalMarks; }
        public double getAttendance() { return attendance; }
        public String getLeafHash() { return leafHash; }

        public static String computeLeafHash(int studentId, String department, String grade, int totalMarks, String salt) {
            String raw = String.format(Locale.US, "AETHERLOCK_LEAF:%d:%s:%s:%d:%s", studentId, department, grade, totalMarks, salt);
            return sha256(raw);
        }
    }

    public static class ProofStep {
        private final String position; // "left" or "right"
        private final String hash;

        public ProofStep(String position, String hash) {
            this.position = position;
            this.hash = hash;
        }

        public String getPosition() { return position; }
        public String getHash() { return hash; }

        public String toJson() {
            return String.format(Locale.US, "{\"position\":\"%s\",\"hash\":\"%s\"}", position, hash);
        }
    }

    private final String termId;
    private final String salt;
    private final List<Leaf> leaves;
    private final List<List<String>> treeLevels;
    private final String rootHash;

    public MerkleTree(String termId, String salt, List<Student> students) {
        this.termId = termId;
        this.salt = salt;
        this.leaves = new ArrayList<>();
        this.treeLevels = new ArrayList<>();

        // Sort students deterministically by ID
        List<Student> sortedStudents = new ArrayList<>(students);
        sortedStudents.sort(Comparator.comparingInt(Student::getStudentId));

        for (Student s : sortedStudents) {
            this.leaves.add(new Leaf(s.getStudentId(), s.getDepartment(), s.getGrade(), s.getTotal(), s.getAttendance(), salt));
        }

        if (this.leaves.isEmpty()) {
            this.rootHash = sha256("EMPTY_TREE:" + termId + ":" + salt);
            this.treeLevels.add(Collections.singletonList(this.rootHash));
        } else {
            this.rootHash = buildTree();
        }
    }

    private String buildTree() {
        List<String> currentLevel = new ArrayList<>();
        for (Leaf leaf : leaves) {
            currentLevel.add(leaf.getLeafHash());
        }
        treeLevels.add(new ArrayList<>(currentLevel));

        while (currentLevel.size() > 1) {
            List<String> nextLevel = new ArrayList<>();
            for (int i = 0; i < currentLevel.size(); i += 2) {
                String left = currentLevel.get(i);
                String right = (i + 1 < currentLevel.size()) ? currentLevel.get(i + 1) : left; // duplicate if odd
                nextLevel.add(hashPair(left, right));
            }
            treeLevels.add(new ArrayList<>(nextLevel));
            currentLevel = nextLevel;
        }

        return currentLevel.get(0);
    }

    public static String hashPair(String left, String right) {
        return sha256(left + right);
    }

    public String getRootHash() {
        return rootHash;
    }

    public String getTermId() {
        return termId;
    }

    public String getSalt() {
        return salt;
    }

    public List<Leaf> getLeaves() {
        return leaves;
    }

    public List<List<String>> getTreeLevels() {
        return treeLevels;
    }

    /**
     * Generates a Merkle Proof (audit path) for a specific student ID.
     */
    public List<ProofStep> getProof(int studentId) {
        int index = -1;
        for (int i = 0; i < leaves.size(); i++) {
            if (leaves.get(i).getStudentId() == studentId) {
                index = i;
                break;
            }
        }

        if (index == -1) {
            return Collections.emptyList();
        }

        List<ProofStep> proof = new ArrayList<>();
        int currentIndex = index;

        for (int level = 0; level < treeLevels.size() - 1; level++) {
            List<String> currentLevelHashes = treeLevels.get(level);
            boolean isRightNode = (currentIndex % 2 == 1);
            int siblingIndex = isRightNode ? currentIndex - 1 : currentIndex + 1;

            if (siblingIndex < currentLevelHashes.size()) {
                String siblingHash = currentLevelHashes.get(siblingIndex);
                proof.add(new ProofStep(isRightNode ? "left" : "right", siblingHash));
            } else {
                // If odd and at edge, duplicated with itself
                String siblingHash = currentLevelHashes.get(currentIndex);
                proof.add(new ProofStep("right", siblingHash));
            }

            currentIndex /= 2;
        }

        return proof;
    }

    /**
     * Stateless verification of a Merkle proof path against an expected root hash.
     */
    public static boolean verifyProof(String leafHash, List<ProofStep> proof, String expectedRoot) {
        if (leafHash == null || expectedRoot == null || proof == null
                || leafHash.trim().isEmpty() || expectedRoot.trim().isEmpty()
                || expectedRoot.length() != 64 || leafHash.length() != 64) {
            return false;
        }

        String currentHash = leafHash;
        for (ProofStep step : proof) {
            if ("left".equalsIgnoreCase(step.getPosition())) {
                currentHash = hashPair(step.getHash(), currentHash);
            } else {
                currentHash = hashPair(currentHash, step.getHash());
            }
        }

        return currentHash.equalsIgnoreCase(expectedRoot);
    }

    public static String sha256(String input) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] encoded = digest.digest(input.getBytes(StandardCharsets.UTF_8));
            StringBuilder sb = new StringBuilder();
            for (byte b : encoded) {
                sb.append(String.format("%02x", b));
            }
            return sb.toString();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("SHA-256 algorithm unavailable", e);
        }
    }
}
