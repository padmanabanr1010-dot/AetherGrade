package security;

import model.Student;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class ZkpVerificationUtil {

    private static final String HMAC_SECRET = "ZKP_PRIVACY_PROOF_SECRET_KEY_2026_HMAC_SHA256_STUDENT_GRADE_SYS";

    public static class TokenClaims {
        private final boolean isEligibleForExam;
        private final boolean hasPassedAll;
        private final String gpaBracket;
        private final long issuanceTime;
        private final long expirationTime;
        private final String tokenId;

        public TokenClaims(boolean isEligibleForExam, boolean hasPassedAll, String gpaBracket, long issuanceTime, long expirationTime, String tokenId) {
            this.isEligibleForExam = isEligibleForExam;
            this.hasPassedAll = hasPassedAll;
            this.gpaBracket = gpaBracket;
            this.issuanceTime = issuanceTime;
            this.expirationTime = expirationTime;
            this.tokenId = tokenId;
        }

        public boolean isEligibleForExam() { return isEligibleForExam; }
        public boolean isHasPassedAll() { return hasPassedAll; }
        public String getGpaBracket() { return gpaBracket; }
        public long getIssuanceTime() { return issuanceTime; }
        public long getExpirationTime() { return expirationTime; }
        public String getTokenId() { return tokenId; }

        public String toJsonPayload() {
            return String.format(Locale.US,
                "{\"is_eligible_for_exam\":%b,\"has_passed_all\":%b,\"gpa_bracket\":\"%s\",\"iat\":%d,\"exp\":%d,\"jti\":\"%s\"}",
                isEligibleForExam, hasPassedAll, gpaBracket, issuanceTime, expirationTime, tokenId
            );
        }
    }

    public static class ClaimVerificationResult {
        private final boolean valid;
        private final TokenClaims claims;
        private final String error;

        public ClaimVerificationResult(boolean valid, TokenClaims claims, String error) {
            this.valid = valid;
            this.claims = claims;
            this.error = error;
        }

        public boolean isValid() { return valid; }
        public TokenClaims getClaims() { return claims; }
        public String getError() { return error; }

        public String toJson() {
            if (!valid) {
                return String.format(Locale.US, "{\"valid\":false,\"error\":\"%s\"}", escapeJson(error));
            }
            return String.format(Locale.US,
                "{\"valid\":true,\"claims\":{\"is_eligible_for_exam\":%b,\"has_passed_all\":%b,\"gpa_bracket\":\"%s\"},\"issuedAt\":%d,\"expiresAt\":%d,\"tokenId\":\"%s\"}",
                claims.isEligibleForExam(), claims.isHasPassedAll(), claims.getGpaBracket(),
                claims.getIssuanceTime(), claims.getExpirationTime(), claims.getTokenId()
            );
        }

        private static String escapeJson(String s) {
            if (s == null) return "";
            return s.replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", "\\n").replace("\r", "\\r");
        }
    }

    public static String generateToken(Student student) {
        return generateToken(student, 86400000L); // 24 hours default validity
    }

    public static String generateToken(Student student, long ttlMillis) {
        boolean eligible = student.getAttendance() >= 75.0;
        boolean passedAll = student.getJavaMarks() >= 50 &&
                student.getOsMarks() >= 50 &&
                student.getMathsMarks() >= 50 &&
                student.getDaaMarks() >= 50 &&
                student.getCaMarks() >= 50 &&
                student.getMlMarks() >= 50;

        double pct = student.getPercentage();
        String gpaBracket;
        if (pct >= 87.5) {
            gpaBracket = "ABOVE_3.5";
        } else if (pct >= 75.0) {
            gpaBracket = "ABOVE_3.0";
        } else if (pct >= 50.0) {
            gpaBracket = "ABOVE_2.0";
        } else {
            gpaBracket = "BELOW_2.0";
        }

        long now = System.currentTimeMillis();
        long exp = now + ttlMillis;
        String tokenId = UUID.randomUUID().toString();

        TokenClaims claims = new TokenClaims(eligible, passedAll, gpaBracket, now, exp, tokenId);
        String jsonPayload = claims.toJsonPayload();

        String payloadB64 = Base64.getUrlEncoder().withoutPadding().encodeToString(jsonPayload.getBytes(StandardCharsets.UTF_8));
        String signatureB64 = hmacSha256(payloadB64, HMAC_SECRET);

        return payloadB64 + "." + signatureB64;
    }

    public static ClaimVerificationResult verifyClaim(String token) {
        if (token == null || token.trim().isEmpty()) {
            return new ClaimVerificationResult(false, null, "Token is missing or empty.");
        }

        String[] parts = token.trim().split("\\.");
        if (parts.length != 2) {
            return new ClaimVerificationResult(false, null, "Malformed token structure. Expected <payload>.<signature>");
        }

        String payloadB64 = parts[0];
        String signatureB64 = parts[1];

        // 1. Verify HMAC Signature
        String expectedSignatureB64 = hmacSha256(payloadB64, HMAC_SECRET);
        if (!constantTimeEquals(expectedSignatureB64, signatureB64)) {
            return new ClaimVerificationResult(false, null, "Invalid cryptographic signature. Token is forged or corrupted.");
        }

        // 2. Decode and Parse Payload
        try {
            byte[] decoded = Base64.getUrlDecoder().decode(payloadB64);
            String json = new String(decoded, StandardCharsets.UTF_8);

            boolean eligible = getJsonBool(json, "is_eligible_for_exam");
            boolean passedAll = getJsonBool(json, "has_passed_all");
            String gpaBracket = getJsonString(json, "gpa_bracket");
            long iat = getJsonLong(json, "iat");
            long exp = getJsonLong(json, "exp");
            String jti = getJsonString(json, "jti");

            // 3. Check Expiration
            if (System.currentTimeMillis() > exp) {
                return new ClaimVerificationResult(false, null, "Verification token has expired.");
            }

            TokenClaims claims = new TokenClaims(eligible, passedAll, gpaBracket, iat, exp, jti);
            return new ClaimVerificationResult(true, claims, null);

        } catch (Exception e) {
            return new ClaimVerificationResult(false, null, "Failed to parse token payload: " + e.getMessage());
        }
    }

    private static String hmacSha256(String data, String secret) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            SecretKeySpec secretKey = new SecretKeySpec(secret.getBytes(StandardCharsets.UTF_8), "HmacSHA256");
            mac.init(secretKey);
            byte[] hash = mac.doFinal(data.getBytes(StandardCharsets.UTF_8));
            return Base64.getUrlEncoder().withoutPadding().encodeToString(hash);
        } catch (Exception e) {
            throw new RuntimeException("HMAC-SHA256 calculation failed", e);
        }
    }

    private static boolean constantTimeEquals(String a, String b) {
        if (a == null || b == null) return false;
        byte[] aBytes = a.getBytes(StandardCharsets.UTF_8);
        byte[] bBytes = b.getBytes(StandardCharsets.UTF_8);
        return MessageDigest.isEqual(aBytes, bBytes);
    }

    private static boolean getJsonBool(String json, String key) {
        Pattern p = Pattern.compile("\"" + key + "\":\\s*(true|false)");
        Matcher m = p.matcher(json);
        return m.find() && Boolean.parseBoolean(m.group(1));
    }

    private static String getJsonString(String json, String key) {
        Pattern p = Pattern.compile("\"" + key + "\":\\s*\"([^\"]*)\"");
        Matcher m = p.matcher(json);
        return m.find() ? m.group(1) : "";
    }

    private static long getJsonLong(String json, String key) {
        Pattern p = Pattern.compile("\"" + key + "\":\\s*(\\d+)");
        Matcher m = p.matcher(json);
        return m.find() ? Long.parseLong(m.group(1)) : 0L;
    }
}
