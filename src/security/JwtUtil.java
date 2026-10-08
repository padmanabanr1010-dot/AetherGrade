package security;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

public class JwtUtil {
    private static final String SECRET_KEY = "SGMS_JWT_SUPER_SECRET_HMAC256_KEY_FOR_SIGNING_TOKENS_2026!";
    private static final long EXPIRATION_TIME_MS = 24 * 60 * 60 * 1000L; // 24 hours

    public static class UserClaims {
        private final String username;
        private final String role;
        private final Integer studentId;

        public UserClaims(String username, String role, Integer studentId) {
            this.username = username;
            this.role = role;
            this.studentId = studentId;
        }

        public String getUsername() { return username; }
        public String getRole() { return role; }
        public Integer getStudentId() { return studentId; }
    }

    public static String generateToken(String username, String role, Integer studentId) {
        long now = System.currentTimeMillis();
        long exp = now + EXPIRATION_TIME_MS;

        String headerJson = "{\"alg\":\"HS256\",\"typ\":\"JWT\"}";
        String payloadJson = String.format(
            "{\"sub\":\"%s\",\"role\":\"%s\",\"studentId\":%s,\"iat\":%d,\"exp\":%d}",
            escapeJson(username), escapeJson(role), studentId == null ? "null" : studentId.toString(), now / 1000, exp / 1000
        );

        String encodedHeader = base64UrlEncode(headerJson.getBytes(StandardCharsets.UTF_8));
        String encodedPayload = base64UrlEncode(payloadJson.getBytes(StandardCharsets.UTF_8));

        String contentToSign = encodedHeader + "." + encodedPayload;
        String signature = hmacSha256(contentToSign, SECRET_KEY);

        return contentToSign + "." + signature;
    }

    public static UserClaims validateToken(String token) {
        if (token == null || token.trim().isEmpty()) return null;
        if (token.startsWith("Bearer ")) {
            token = token.substring(7).trim();
        }

        String[] parts = token.split("\\.");
        if (parts.length != 3) return null;

        String headerB64 = parts[0];
        String payloadB64 = parts[1];
        String signatureB64 = parts[2];

        String expectedSignature = hmacSha256(headerB64 + "." + payloadB64, SECRET_KEY);
        if (!constantTimeEquals(signatureB64, expectedSignature)) {
            return null; // Invalid signature
        }

        try {
            String payloadJson = new String(base64UrlDecode(payloadB64), StandardCharsets.UTF_8);
            
            long expSec = extractLongFromJson(payloadJson, "exp");
            if (expSec > 0 && (System.currentTimeMillis() / 1000) > expSec) {
                return null; // Expired token
            }

            String username = extractStringFromJson(payloadJson, "sub");
            String role = extractStringFromJson(payloadJson, "role");
            Integer studentId = extractIntegerFromJson(payloadJson, "studentId");

            return new UserClaims(username, role, studentId);
        } catch (Exception e) {
            return null;
        }
    }

    private static String hmacSha256(String data, String key) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            SecretKeySpec secretKeySpec = new SecretKeySpec(key.getBytes(StandardCharsets.UTF_8), "HmacSHA256");
            mac.init(secretKeySpec);
            byte[] rawHmac = mac.doFinal(data.getBytes(StandardCharsets.UTF_8));
            return base64UrlEncode(rawHmac);
        } catch (Exception e) {
            throw new RuntimeException("HMAC-SHA256 signing failed", e);
        }
    }

    private static String base64UrlEncode(byte[] bytes) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    private static byte[] base64UrlDecode(String str) {
        return Base64.getUrlDecoder().decode(str);
    }

    private static boolean constantTimeEquals(String a, String b) {
        if (a == null || b == null) return false;
        byte[] aBytes = a.getBytes(StandardCharsets.UTF_8);
        byte[] bBytes = b.getBytes(StandardCharsets.UTF_8);
        int result = aBytes.length ^ bBytes.length;
        for (int i = 0; i < aBytes.length && i < bBytes.length; i++) {
            result |= aBytes[i] ^ bBytes[i];
        }
        return result == 0;
    }

    private static String extractStringFromJson(String json, String key) {
        String pattern = "\"" + key + "\":\"";
        int start = json.indexOf(pattern);
        if (start == -1) return null;
        start += pattern.length();
        int end = json.indexOf("\"", start);
        if (end == -1) return null;
        return json.substring(start, end);
    }

    private static Integer extractIntegerFromJson(String json, String key) {
        String pattern = "\"" + key + "\":";
        int start = json.indexOf(pattern);
        if (start == -1) return null;
        start += pattern.length();
        int end1 = json.indexOf(",", start);
        int end2 = json.indexOf("}", start);
        int end = (end1 == -1) ? end2 : (end2 == -1 ? end1 : Math.min(end1, end2));
        if (end == -1) return null;
        String valStr = json.substring(start, end).trim();
        if ("null".equals(valStr)) return null;
        try {
            return Integer.parseInt(valStr);
        } catch (NumberFormatException e) {
            return null;
        }
    }

    private static long extractLongFromJson(String json, String key) {
        Integer val = extractIntegerFromJson(json, key);
        return val == null ? 0L : val.longValue();
    }

    private static String escapeJson(String s) {
        if (s == null) return "";
        return s.replace("\\", "\\\\").replace("\"", "\\\"");
    }
}
