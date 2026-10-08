package web;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;
import repository.StudentRepository;
import repository.JdbcStudentRepository;
import exceptions.DuplicateStudentException;
import exceptions.InvalidAttendanceException;
import exceptions.InvalidMarksException;
import exceptions.StudentNotFoundException;
import model.AcademicStudent;
import model.Student;
import security.*;
import factory.*;
import observer.*;
import audit.AuditLogger;
import audit.AuditLedgerUtil;
import security.ZkpVerificationUtil;

import java.io.*;
import java.net.InetSocketAddress;
import java.sql.SQLException;
import java.util.*;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class WebServer {
    private static final int PORT = 8080;
    private static final StudentRepository repository = new JdbcStudentRepository();
    private static final AuthService authService = new AuthService();
    private static final ExecutorService reportExecutor = Executors.newSingleThreadExecutor();

    // Multi-threading state for background report generator
    private static volatile String reportStatus = "IDLE"; // IDLE, RUNNING, COMPLETED
    private static volatile int reportProgress = 0; // 0 to 100
    private static volatile String generatedReportCsv = "";

    public static void start() throws IOException {
        HttpServer server = HttpServer.create(new InetSocketAddress(PORT), 0);

        // Authentication Endpoints
        server.createContext("/api/auth/login", new AuthApiHandler());
        server.createContext("/api/auth/me", new AuthMeHandler());

        // API Endpoints
        server.createContext("/api/students", new StudentApiHandler());
        server.createContext("/api/stats", new StatsApiHandler());
        server.createContext("/api/report/generate", new GenerateReportHandler());
        server.createContext("/api/report/status", new ReportStatusHandler());
        server.createContext("/api/report/download", new DownloadReportHandler());

        // Immutable Audit Ledger & ZKP Privacy Endpoints
        server.createContext("/api/v1/audit/verify", new AuditVerifyHandler());
        server.createContext("/api/v1/audit/ledger", new AuditLedgerListHandler());
        server.createContext("/api/v1/verify-claim", new VerifyClaimHandler());
        server.createContext("/api/v1/student/zkp-token", new GenerateZkpTokenHandler());
        server.createContext("/api/public/reportcard", new PublicReportCardHandler());

        // AetherLock & Zero-Trust Verification Portal Endpoints
        server.createContext("/api/v1/aetherlock/seal-term", new AetherLockSealHandler());
        server.createContext("/api/v1/aetherlock/status", new AetherLockStatusHandler());
        server.createContext("/api/v1/aetherlock/verify-proof", new AetherLockVerifyProofHandler());
        server.createContext("/api/v1/aetherlock/generate-credential", new AetherLockGenerateCredentialHandler());

        // Static Files Handler
        server.createContext("/", new StaticFileHandler());

        // Executor for handling HTTP requests asynchronously
        server.setExecutor(Executors.newCachedThreadPool());
        server.start();
        System.out.println("Web Server started on http://localhost:" + PORT);
    }

    private static void applySecurityHeaders(HttpExchange exchange) {
        exchange.getResponseHeaders().set("X-Content-Type-Options", "nosniff");
        exchange.getResponseHeaders().set("X-Frame-Options", "DENY");
        exchange.getResponseHeaders().set("X-XSS-Protection", "1; mode=block");
        exchange.getResponseHeaders().set("Access-Control-Allow-Origin", "*");
        exchange.getResponseHeaders().set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS");
        exchange.getResponseHeaders().set("Access-Control-Allow-Headers", "Content-Type, Authorization");
    }

    private static JwtUtil.UserClaims authenticateRequest(HttpExchange exchange) {
        String authHeader = exchange.getRequestHeaders().getFirst("Authorization");
        return JwtUtil.validateToken(authHeader);
    }

    private static String getClientIp(HttpExchange exchange) {
        String forwarded = exchange.getRequestHeaders().getFirst("X-Forwarded-For");
        if (forwarded != null && !forwarded.isEmpty()) {
            return forwarded.split(",")[0].trim();
        }
        InetSocketAddress remote = exchange.getRemoteAddress();
        return remote != null ? remote.getAddress().getHostAddress() : "127.0.0.1";
    }

    // Handler for Authentication API (/api/auth/login)
    static class AuthApiHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            applySecurityHeaders(exchange);
            String method = exchange.getRequestMethod();

            if ("OPTIONS".equalsIgnoreCase(method)) {
                sendResponse(exchange, 204, "");
                return;
            }

            if (!"POST".equalsIgnoreCase(method)) {
                sendResponse(exchange, 405, "{\"error\":\"Method Not Allowed\"}");
                return;
            }

            String clientIp = getClientIp(exchange);
            // Rate limit: Max 5 login attempts per minute per IP
            if (!RateLimiter.allowRequest("LOGIN_" + clientIp, 5, 60000)) {
                AuditLogger.log("ANONYMOUS", "GUEST", "LOGIN_BLOCKED", "/api/auth/login", clientIp, "RATE_LIMITED", "Exceeded login rate limit");
                sendResponse(exchange, 429, "{\"error\":\"Too many login attempts. Please try again later.\"}");
                return;
            }

            String body = getBody(exchange);
            String username = getJsonString(body, "username");
            String password = getJsonString(body, "password");

            AuthService.LoginResult result = authService.authenticate(username, password);

            if (result.isSuccess()) {
                AuditLogger.log(result.getUsername(), result.getRole(), "LOGIN_SUCCESS", "/api/auth/login", clientIp, "SUCCESS", "User authenticated");
                sendJsonResponse(exchange, 200, result.toJson());
            } else {
                AuditLogger.log(username, "GUEST", "LOGIN_FAILED", "/api/auth/login", clientIp, "FAILURE", "Invalid credentials");
                sendJsonResponse(exchange, 401, result.toJson());
            }
        }
    }

    // Handler for checking active user session (/api/auth/me)
    static class AuthMeHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            applySecurityHeaders(exchange);
            if ("OPTIONS".equalsIgnoreCase(exchange.getRequestMethod())) {
                sendResponse(exchange, 204, "");
                return;
            }

            JwtUtil.UserClaims claims = authenticateRequest(exchange);
            if (claims == null) {
                sendJsonResponse(exchange, 401, "{\"authenticated\":false}");
                return;
            }

            String json = String.format(
                "{\"authenticated\":true,\"username\":\"%s\",\"role\":\"%s\",\"studentId\":%s}",
                escapeJson(claims.getUsername()), escapeJson(claims.getRole()),
                claims.getStudentId() == null ? "null" : claims.getStudentId()
            );
            sendJsonResponse(exchange, 200, json);
        }
    }

    // Handler for Serving Frontend Web Assets
    static class StaticFileHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            applySecurityHeaders(exchange);
            String path = exchange.getRequestURI().getPath();
            if (path.equals("/")) {
                path = "/index.html";
            }

            File file = new File("webroot" + path);
            if (!file.exists() || file.isDirectory()) {
                sendResponse(exchange, 404, "404 Not Found");
                return;
            }

            String mimeType = "text/plain";
            if (path.endsWith(".html")) mimeType = "text/html";
            else if (path.endsWith(".css")) mimeType = "text/css";
            else if (path.endsWith(".js")) mimeType = "application/javascript";
            else if (path.endsWith(".png")) mimeType = "image/png";

            exchange.getResponseHeaders().set("Content-Type", mimeType);
            exchange.sendResponseHeaders(200, file.length());

            try (InputStream is = new FileInputStream(file);
                 OutputStream os = exchange.getResponseBody()) {
                byte[] buffer = new byte[4096];
                int count;
                while ((count = is.read(buffer)) != -1) {
                    os.write(buffer, 0, count);
                }
            }
        }
    }

    // Handler for Student CRUD operations
    static class StudentApiHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            applySecurityHeaders(exchange);
            String method = exchange.getRequestMethod();

            if ("OPTIONS".equalsIgnoreCase(method)) {
                sendResponse(exchange, 204, "");
                return;
            }

            JwtUtil.UserClaims claims = authenticateRequest(exchange);
            if (claims == null) {
                sendJsonResponse(exchange, 401, "{\"error\":\"Unauthorized: Valid JWT Bearer token required\"}");
                return;
            }

            String clientIp = getClientIp(exchange);
            String path = exchange.getRequestURI().getPath();

            // RBAC Check: Restrict system to Faculty and Admin roles
            if ("STUDENT".equalsIgnoreCase(claims.getRole())) {
                AuditLogger.log(claims.getUsername(), claims.getRole(), "UNAUTHORIZED_ACCESS_ATTEMPT", path, clientIp, "FORBIDDEN", "Student account attempted access");
                sendJsonResponse(exchange, 403, "{\"error\":\"Forbidden: Application is restricted to Faculty and Admin only.\"}");
                return;
            }

            try {
                if (path.endsWith("/marks") || path.contains("/marks")) {
                    if ("PUT".equalsIgnoreCase(method) || "POST".equalsIgnoreCase(method)) {
                        handleUpdateMarks(exchange, claims, clientIp);
                        return;
                    }
                }

                if ("GET".equalsIgnoreCase(method)) {
                    handleGet(exchange, claims);
                } else if ("POST".equalsIgnoreCase(method)) {
                    handlePost(exchange, claims, clientIp);
                } else if ("PUT".equalsIgnoreCase(method)) {
                    handlePut(exchange, claims, clientIp);
                } else if ("DELETE".equalsIgnoreCase(method)) {
                    handleDelete(exchange, claims, clientIp);
                } else {
                    sendJsonResponse(exchange, 405, "{\"error\":\"Method Not Allowed\"}");
                }
            } catch (Exception e) {
                sendErrorResponse(exchange, e);
            }
        }

        private void handleGet(HttpExchange exchange, JwtUtil.UserClaims claims) throws SQLException, IOException, StudentNotFoundException {
            Map<String, String> params = parseQueryParams(exchange.getRequestURI().getQuery());

            if (params.containsKey("id")) {
                int studentId = Integer.parseInt(params.get("id"));
                Student s = repository.getStudent(studentId);
                sendJsonResponse(exchange, 200, s.toJson());
                return;
            }

            String sortBy = params.getOrDefault("sort", "id");

            List<Student> students;
            if ("name".equalsIgnoreCase(sortBy)) {
                students = repository.getAllStudentsSortedByName();
            } else if ("percentage".equalsIgnoreCase(sortBy)) {
                students = repository.getAllStudentsSortedByPercentage();
            } else {
                students = repository.getAllStudents();
            }

            StringBuilder sb = new StringBuilder("[");
            for (int i = 0; i < students.size(); i++) {
                sb.append(students.get(i).toJson());
                if (i < students.size() - 1) sb.append(",");
            }
            sb.append("]");

            sendJsonResponse(exchange, 200, sb.toString());
        }

        private void handlePost(HttpExchange exchange, JwtUtil.UserClaims claims, String clientIp) throws IOException, SQLException, InvalidMarksException, InvalidAttendanceException, DuplicateStudentException {
            String body = getBody(exchange);
            int studentId = getJsonInt(body, "studentId");
            String name = getJsonString(body, "name");
            String department = getJsonString(body, "department");
            int year = getJsonInt(body, "year");
            int javaMarks = getJsonInt(body, "javaMarks");
            int osMarks = getJsonInt(body, "osMarks");
            int mathsMarks = getJsonInt(body, "mathsMarks");
            int daaMarks = getJsonInt(body, "daaMarks");
            int caMarks = getJsonInt(body, "caMarks");
            int mlMarks = getJsonInt(body, "mlMarks");
            double attendance = getJsonDouble(body, "attendance");

            if (javaMarks < 0 || javaMarks > 100) throw new InvalidMarksException("Java Marks must be between 0 and 100.");
            if (osMarks < 0 || osMarks > 100) throw new InvalidMarksException("OS Marks must be between 0 and 100.");
            if (mathsMarks < 0 || mathsMarks > 100) throw new InvalidMarksException("Maths Marks must be between 0 and 100.");
            if (daaMarks < 0 || daaMarks > 100) throw new InvalidMarksException("DAA Marks must be between 0 and 100.");
            if (caMarks < 0 || caMarks > 100) throw new InvalidMarksException("CA Marks must be between 0 and 100.");
            if (mlMarks < 0 || mlMarks > 100) throw new InvalidMarksException("ML Marks must be between 0 and 100.");
            if (attendance < 0.0 || attendance > 100.0) throw new InvalidAttendanceException("Attendance Percentage must be between 0 and 100.");

            Student student = new AcademicStudent(studentId, name, department, year, javaMarks, osMarks, mathsMarks, daaMarks, caMarks, mlMarks, attendance);
            repository.addStudent(student);

            // Observer Pattern check
            LowAttendanceNotifier.checkAndNotify(student);

            AuditLogger.log(claims.getUsername(), claims.getRole(), "ADD_STUDENT", "Student ID: " + studentId, clientIp, "SUCCESS", "Added student " + name);

            sendJsonResponse(exchange, 201, "{\"message\":\"Student added successfully\"}");
        }

        private void handlePut(HttpExchange exchange, JwtUtil.UserClaims claims, String clientIp) throws IOException, SQLException, InvalidMarksException, InvalidAttendanceException, StudentNotFoundException {
            String body = getBody(exchange);
            int studentId = getJsonInt(body, "studentId");
            
            Student existing = repository.getStudent(studentId);

            String name = getJsonString(body, "name");
            if (name == null || name.trim().isEmpty()) name = existing.getName();

            String department = getJsonString(body, "department");
            if (department == null || department.trim().isEmpty()) department = existing.getDepartment();

            int year = getJsonInt(body, "year");
            if (year <= 0) year = existing.getYear();

            int javaMarks = body.contains("\"javaMarks\"") ? getJsonInt(body, "javaMarks") : existing.getJavaMarks();
            int osMarks = body.contains("\"osMarks\"") ? getJsonInt(body, "osMarks") : existing.getOsMarks();
            int mathsMarks = body.contains("\"mathsMarks\"") ? getJsonInt(body, "mathsMarks") : existing.getMathsMarks();
            int daaMarks = body.contains("\"daaMarks\"") ? getJsonInt(body, "daaMarks") : existing.getDaaMarks();
            int caMarks = body.contains("\"caMarks\"") ? getJsonInt(body, "caMarks") : existing.getCaMarks();
            int mlMarks = body.contains("\"mlMarks\"") ? getJsonInt(body, "mlMarks") : existing.getMlMarks();

            double attendance = body.contains("\"attendance\"") ? getJsonDouble(body, "attendance") : existing.getAttendance();

            if (javaMarks < 0 || javaMarks > 100) throw new InvalidMarksException("Java Marks must be between 0 and 100.");
            if (osMarks < 0 || osMarks > 100) throw new InvalidMarksException("OS Marks must be between 0 and 100.");
            if (mathsMarks < 0 || mathsMarks > 100) throw new InvalidMarksException("Maths Marks must be between 0 and 100.");
            if (daaMarks < 0 || daaMarks > 100) throw new InvalidMarksException("DAA Marks must be between 0 and 100.");
            if (caMarks < 0 || caMarks > 100) throw new InvalidMarksException("CA Marks must be between 0 and 100.");
            if (mlMarks < 0 || mlMarks > 100) throw new InvalidMarksException("ML Marks must be between 0 and 100.");
            if (attendance < 0.0 || attendance > 100.0) throw new InvalidAttendanceException("Attendance Percentage must be between 0 and 100.");

            Student student = new AcademicStudent(studentId, name, department, year, javaMarks, osMarks, mathsMarks, daaMarks, caMarks, mlMarks, attendance);
            repository.updateStudent(student);

            // Observer Pattern check
            LowAttendanceNotifier.checkAndNotify(student);

            AuditLogger.log(claims.getUsername(), claims.getRole(), "UPDATE_STUDENT", "Student ID: " + studentId, clientIp, "SUCCESS", "Updated student profile");

            sendJsonResponse(exchange, 200, "{\"message\":\"Student updated successfully\"}");
        }

        private void handleUpdateMarks(HttpExchange exchange, JwtUtil.UserClaims claims, String clientIp) throws IOException, SQLException, InvalidMarksException, StudentNotFoundException {
            String body = getBody(exchange);
            int studentId = getJsonInt(body, "studentId");
            int javaMarks = getJsonInt(body, "javaMarks");
            int osMarks = getJsonInt(body, "osMarks");
            int mathsMarks = getJsonInt(body, "mathsMarks");
            int daaMarks = getJsonInt(body, "daaMarks");
            int caMarks = getJsonInt(body, "caMarks");
            int mlMarks = getJsonInt(body, "mlMarks");

            if (studentId <= 0) {
                sendJsonResponse(exchange, 400, "{\"error\":\"Invalid Student ID\"}");
                return;
            }
            if (javaMarks < 0 || javaMarks > 100) throw new InvalidMarksException("Java Marks must be between 0 and 100.");
            if (osMarks < 0 || osMarks > 100) throw new InvalidMarksException("OS Marks must be between 0 and 100.");
            if (mathsMarks < 0 || mathsMarks > 100) throw new InvalidMarksException("Maths Marks must be between 0 and 100.");
            if (daaMarks < 0 || daaMarks > 100) throw new InvalidMarksException("DAA Marks must be between 0 and 100.");
            if (caMarks < 0 || caMarks > 100) throw new InvalidMarksException("CA Marks must be between 0 and 100.");
            if (mlMarks < 0 || mlMarks > 100) throw new InvalidMarksException("ML Marks must be between 0 and 100.");

            repository.updateStudentMarks(studentId, javaMarks, osMarks, mathsMarks, daaMarks, caMarks, mlMarks);

            Student updated = repository.getStudent(studentId);
            
            AuditLogger.log(claims.getUsername(), claims.getRole(), "UPDATE_MARKS", "Student ID: " + studentId, clientIp, "SUCCESS", "Updated student marks");

            String jsonResponse = String.format(java.util.Locale.US, "{\"message\":\"Student marks updated successfully\",\"student\":%s}", updated.toJson());
            sendJsonResponse(exchange, 200, jsonResponse);
        }

        private void handleDelete(HttpExchange exchange, JwtUtil.UserClaims claims, String clientIp) throws SQLException, IOException, StudentNotFoundException {
            Map<String, String> params = parseQueryParams(exchange.getRequestURI().getQuery());
            if (!params.containsKey("id")) {
                sendJsonResponse(exchange, 400, "{\"error\":\"Missing student id parameter\"}");
                return;
            }
            int studentId = Integer.parseInt(params.get("id"));
            repository.deleteStudent(studentId);

            AuditLogger.log(claims.getUsername(), claims.getRole(), "DELETE_STUDENT", "Student ID: " + studentId, clientIp, "SUCCESS", "Deleted student");

            sendJsonResponse(exchange, 200, "{\"message\":\"Student deleted successfully\"}");
        }
    }

    // Handler for overall stats and department averages
    static class StatsApiHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            applySecurityHeaders(exchange);
            if ("OPTIONS".equalsIgnoreCase(exchange.getRequestMethod())) {
                sendResponse(exchange, 204, "");
                return;
            }

            if (!"GET".equalsIgnoreCase(exchange.getRequestMethod())) {
                sendJsonResponse(exchange, 405, "{\"error\":\"Method Not Allowed\"}");
                return;
            }

            JwtUtil.UserClaims claims = authenticateRequest(exchange);
            if (claims == null) {
                sendJsonResponse(exchange, 401, "{\"error\":\"Unauthorized: Valid JWT Bearer token required\"}");
                return;
            }

            try {
                List<Student> students = repository.getAllStudents();
                int totalStudents = students.size();
                
                double avgPercentage = students.stream()
                        .mapToDouble(Student::getPercentage)
                        .average()
                        .orElse(0.0);

                long passCount = students.stream()
                        .filter(s -> !"FAIL".equals(s.getGrade()))
                        .count();

                double passRate = totalStudents == 0 ? 0.0 : ((double) passCount / totalStudents) * 100.0;

                long lowAttendanceCount = students.stream()
                        .filter(s -> s.getAttendance() < 75.0)
                        .count();

                Map<String, Map<String, Object>> deptStats = repository.getDepartmentStatistics();
                
                StringBuilder sb = new StringBuilder();
                sb.append("{");
                sb.append(String.format(java.util.Locale.US, "\"totalStudents\":%d,", totalStudents));
                sb.append(String.format(java.util.Locale.US, "\"averagePercentage\":%.2f,", avgPercentage));
                sb.append(String.format(java.util.Locale.US, "\"passRate\":%.2f,", passRate));
                sb.append(String.format(java.util.Locale.US, "\"lowAttendanceCount\":%d,", lowAttendanceCount));
                sb.append("\"departmentStats\":{");
                
                int deptIdx = 0;
                for (Map.Entry<String, Map<String, Object>> entry : deptStats.entrySet()) {
                    String dept = entry.getKey();
                    Map<String, Object> stats = entry.getValue();
                    sb.append(String.format(java.util.Locale.US, "\"%s\":{", escapeJson(dept)));
                    sb.append(String.format(java.util.Locale.US, "\"studentCount\":%d,", stats.get("studentCount")));
                    sb.append(String.format(java.util.Locale.US, "\"averagePercentage\":%.2f,", stats.get("averagePercentage")));
                    sb.append(String.format(java.util.Locale.US, "\"passRate\":%.2f", stats.get("passRate")));
                    sb.append("}");
                    if (deptIdx < deptStats.size() - 1) sb.append(",");
                    deptIdx++;
                }
                sb.append("}");
                sb.append("}");

                sendJsonResponse(exchange, 200, sb.toString());
            } catch (Exception e) {
                sendErrorResponse(exchange, e);
            }
        }
    }

    // Handler for asynchronous multi-threaded report generator (Factory + Executor)
    static class GenerateReportHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            applySecurityHeaders(exchange);
            if ("OPTIONS".equalsIgnoreCase(exchange.getRequestMethod())) {
                sendResponse(exchange, 204, "");
                return;
            }

            if (!"POST".equalsIgnoreCase(exchange.getRequestMethod())) {
                sendJsonResponse(exchange, 405, "{\"error\":\"Method Not Allowed\"}");
                return;
            }

            JwtUtil.UserClaims claims = authenticateRequest(exchange);
            if (claims == null) {
                sendJsonResponse(exchange, 401, "{\"error\":\"Unauthorized\"}");
                return;
            }

            if ("RUNNING".equals(reportStatus)) {
                sendJsonResponse(exchange, 409, "{\"error\":\"Report generation already in progress\"}");
                return;
            }

            String clientIp = getClientIp(exchange);
            if (!RateLimiter.allowRequest("REPORT_" + clientIp, 2, 60000)) {
                sendJsonResponse(exchange, 429, "{\"error\":\"Rate limit exceeded for report generation.\"}");
                return;
            }

            reportStatus = "RUNNING";
            reportProgress = 0;

            reportExecutor.submit(() -> {
                try {
                    reportProgress = 25;
                    Thread.sleep(500);

                    List<Student> students = repository.getAllStudents();
                    reportProgress = 50;
                    Thread.sleep(500);

                    // Factory Pattern for report generation
                    ReportGenerator generator = ReportFactory.getReportGenerator(ReportFactory.ReportType.CSV);
                    generatedReportCsv = generator.generateReport(students);

                    reportProgress = 75;
                    Thread.sleep(500);

                    reportProgress = 100;
                    reportStatus = "COMPLETED";

                    AuditLogger.log(claims.getUsername(), claims.getRole(), "GENERATE_REPORT", "CSV Export", clientIp, "SUCCESS", "Generated CSV report");
                } catch (Exception e) {
                    reportStatus = "FAILED";
                    AuditLogger.log(claims.getUsername(), claims.getRole(), "GENERATE_REPORT", "CSV Export", clientIp, "FAILED", e.getMessage());
                }
            });

            sendJsonResponse(exchange, 202, "{\"message\":\"Report generation started\"}");
        }
    }

    static class ReportStatusHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            applySecurityHeaders(exchange);
            if (!"GET".equalsIgnoreCase(exchange.getRequestMethod())) {
                sendJsonResponse(exchange, 405, "{\"error\":\"Method Not Allowed\"}");
                return;
            }

            String response = String.format(java.util.Locale.US, "{\"status\":\"%s\",\"progress\":%d}", reportStatus, reportProgress);
            sendJsonResponse(exchange, 200, response);
        }
    }

    static class DownloadReportHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            applySecurityHeaders(exchange);
            if (!"GET".equalsIgnoreCase(exchange.getRequestMethod())) {
                sendJsonResponse(exchange, 405, "{\"error\":\"Method Not Allowed\"}");
                return;
            }

            if (!"COMPLETED".equals(reportStatus)) {
                sendJsonResponse(exchange, 400, "{\"error\":\"Report is not ready for download\"}");
                return;
            }

            byte[] csvBytes = generatedReportCsv.getBytes("UTF-8");
            exchange.getResponseHeaders().set("Content-Type", "text/csv");
            exchange.getResponseHeaders().set("Content-Disposition", "attachment; filename=\"Student_Grade_Report.csv\"");
            exchange.sendResponseHeaders(200, csvBytes.length);
            try (OutputStream os = exchange.getResponseBody()) {
                os.write(csvBytes);
            }
        }
    }

    // Handler for Audit Ledger Hash Chain Verification (GET /api/v1/audit/verify)
    static class AuditVerifyHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            applySecurityHeaders(exchange);
            if ("OPTIONS".equalsIgnoreCase(exchange.getRequestMethod())) {
                sendResponse(exchange, 204, "");
                return;
            }

            if (!"GET".equalsIgnoreCase(exchange.getRequestMethod())) {
                sendJsonResponse(exchange, 405, "{\"error\":\"Method Not Allowed\"}");
                return;
            }

            JwtUtil.UserClaims claims = authenticateRequest(exchange);
            if (claims == null) {
                sendJsonResponse(exchange, 401, "{\"error\":\"Unauthorized: JWT Bearer token required\"}");
                return;
            }

            AuditLedgerUtil.VerificationResult result = AuditLedgerUtil.verifyChain();
            AuditLogger.log(claims.getUsername(), claims.getRole(), "VERIFY_AUDIT_LEDGER", "/api/v1/audit/verify",
                    getClientIp(exchange), result.isValid() ? "SUCCESS" : "TAMPER_DETECTED", result.getDetails());

            sendJsonResponse(exchange, 200, result.toJson());
        }
    }

    // Handler for retrieving full Audit Ledger blocks (GET /api/v1/audit/ledger)
    static class AuditLedgerListHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            applySecurityHeaders(exchange);
            if ("OPTIONS".equalsIgnoreCase(exchange.getRequestMethod())) {
                sendResponse(exchange, 204, "");
                return;
            }

            if (!"GET".equalsIgnoreCase(exchange.getRequestMethod())) {
                sendJsonResponse(exchange, 405, "{\"error\":\"Method Not Allowed\"}");
                return;
            }

            JwtUtil.UserClaims claims = authenticateRequest(exchange);
            if (claims == null) {
                sendJsonResponse(exchange, 401, "{\"error\":\"Unauthorized: JWT Bearer token required\"}");
                return;
            }

            List<AuditLedgerUtil.LedgerEntry> entries = AuditLedgerUtil.getAllEntries();
            StringBuilder sb = new StringBuilder("[");
            for (int i = 0; i < entries.size(); i++) {
                sb.append(entries.get(i).toJson());
                if (i < entries.size() - 1) sb.append(",");
            }
            sb.append("]");

            sendJsonResponse(exchange, 200, sb.toString());
        }
    }

    // Public (unauthenticated) endpoint for Third-Party Claim Verification (POST /api/v1/verify-claim)
    static class VerifyClaimHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            applySecurityHeaders(exchange);
            if ("OPTIONS".equalsIgnoreCase(exchange.getRequestMethod())) {
                sendResponse(exchange, 204, "");
                return;
            }

            if (!"POST".equalsIgnoreCase(exchange.getRequestMethod())) {
                sendJsonResponse(exchange, 405, "{\"error\":\"Method Not Allowed\"}");
                return;
            }

            String body = getBody(exchange);
            String token = getJsonString(body, "token");

            ZkpVerificationUtil.ClaimVerificationResult result = ZkpVerificationUtil.verifyClaim(token);
            sendJsonResponse(exchange, 200, result.toJson());
        }
    }

    // Public Endpoint for Student Report Card Generator (GET /api/public/reportcard?id=101)
    static class PublicReportCardHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            applySecurityHeaders(exchange);
            if ("OPTIONS".equalsIgnoreCase(exchange.getRequestMethod())) {
                sendResponse(exchange, 204, "");
                return;
            }

            if (!"GET".equalsIgnoreCase(exchange.getRequestMethod())) {
                sendJsonResponse(exchange, 405, "{\"error\":\"Method Not Allowed\"}");
                return;
            }

            Map<String, String> params = parseQueryParams(exchange.getRequestURI().getQuery());
            if (!params.containsKey("id")) {
                sendJsonResponse(exchange, 400, "{\"error\":\"Missing student ID parameter\"}");
                return;
            }

            try {
                int studentId = Integer.parseInt(params.get("id"));
                Student s = repository.getStudent(studentId);
                sendJsonResponse(exchange, 200, s.toJson());
            } catch (StudentNotFoundException e) {
                sendJsonResponse(exchange, 404, "{\"error\":\"Student record not found with ID " + params.get("id") + "\"}");
            } catch (Exception e) {
                sendErrorResponse(exchange, e);
            }
        }
    }

    // Handler for generating ZKP assertion token for a student (POST /api/v1/student/zkp-token)
    static class GenerateZkpTokenHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            applySecurityHeaders(exchange);
            if ("OPTIONS".equalsIgnoreCase(exchange.getRequestMethod())) {
                sendResponse(exchange, 204, "");
                return;
            }

            if (!"POST".equalsIgnoreCase(exchange.getRequestMethod()) && !"GET".equalsIgnoreCase(exchange.getRequestMethod())) {
                sendJsonResponse(exchange, 405, "{\"error\":\"Method Not Allowed\"}");
                return;
            }

            JwtUtil.UserClaims claims = authenticateRequest(exchange);
            if (claims == null) {
                sendJsonResponse(exchange, 401, "{\"error\":\"Unauthorized: JWT Bearer token required\"}");
                return;
            }

            Map<String, String> params = parseQueryParams(exchange.getRequestURI().getQuery());
            String body = getBody(exchange);

            int studentId = 0;
            if (params.containsKey("studentId")) {
                studentId = Integer.parseInt(params.get("studentId"));
            } else if (body.contains("studentId")) {
                studentId = getJsonInt(body, "studentId");
            } else if ("STUDENT".equalsIgnoreCase(claims.getRole()) && claims.getStudentId() != null) {
                studentId = claims.getStudentId();
            }

            if (studentId <= 0) {
                sendJsonResponse(exchange, 400, "{\"error\":\"Invalid or missing studentId\"}");
                return;
            }

            // Students can only generate tokens for themselves
            if ("STUDENT".equalsIgnoreCase(claims.getRole()) && claims.getStudentId() != null && claims.getStudentId() != studentId) {
                sendJsonResponse(exchange, 403, "{\"error\":\"Forbidden: Students can only generate assertion tokens for their own profile.\"}");
                return;
            }

            try {
                Student s = repository.getStudent(studentId);
                String token = ZkpVerificationUtil.generateToken(s);
                String json = String.format(Locale.US,
                    "{\"success\":true,\"studentId\":%d,\"token\":\"%s\",\"message\":\"Privacy-preserving ZKP token generated successfully\"}",
                    studentId, token
                );
                sendJsonResponse(exchange, 200, json);
            } catch (StudentNotFoundException e) {
                sendJsonResponse(exchange, 404, "{\"error\":\"Student not found with ID " + studentId + "\"}");
            } catch (Exception e) {
                sendErrorResponse(exchange, e);
            }
        }
    }

    // Handler for Sealing Term via AetherLock (POST /api/v1/aetherlock/seal-term)
    static class AetherLockSealHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            applySecurityHeaders(exchange);
            if ("OPTIONS".equalsIgnoreCase(exchange.getRequestMethod())) {
                sendResponse(exchange, 204, "");
                return;
            }

            if (!"POST".equalsIgnoreCase(exchange.getRequestMethod())) {
                sendJsonResponse(exchange, 405, "{\"error\":\"Method Not Allowed\"}");
                return;
            }

            JwtUtil.UserClaims claims = authenticateRequest(exchange);
            if (claims == null) {
                sendJsonResponse(exchange, 401, "{\"error\":\"Unauthorized: JWT Bearer token required\"}");
                return;
            }

            if (!"ADMIN".equalsIgnoreCase(claims.getRole()) && !"FACULTY".equalsIgnoreCase(claims.getRole())) {
                sendJsonResponse(exchange, 403, "{\"error\":\"Forbidden: Only Admin or Faculty can seal terms.\"}");
                return;
            }

            String body = getBody(exchange);
            String termId = getJsonString(body, "termId");
            if (termId == null || termId.trim().isEmpty()) {
                termId = "SPRING-2026";
            }

            try {
                AetherLockService.SealResponse response = AetherLockService.sealTerm(termId, claims.getUsername(), repository);
                
                StringBuilder sb = new StringBuilder();
                sb.append("{\"success\":true,");
                sb.append("\"seal\":").append(response.getSeal().toJson()).append(",");
                
                // Tree levels for visualization
                sb.append("\"treeLevels\":[");
                List<List<String>> levels = response.getTreeLevels();
                for (int l = 0; l < levels.size(); l++) {
                    sb.append("[");
                    List<String> hashes = levels.get(l);
                    for (int h = 0; h < hashes.size(); h++) {
                        sb.append("\"").append(hashes.get(h)).append("\"");
                        if (h < hashes.size() - 1) sb.append(",");
                    }
                    sb.append("]");
                    if (l < levels.size() - 1) sb.append(",");
                }
                sb.append("],");

                // Student leaves
                sb.append("\"studentLeaves\":[");
                List<Map<String, Object>> leaves = response.getStudentLeaves();
                for (int i = 0; i < leaves.size(); i++) {
                    Map<String, Object> lf = leaves.get(i);
                    sb.append(String.format(Locale.US,
                        "{\"studentId\":%d,\"department\":\"%s\",\"grade\":\"%s\",\"totalMarks\":%d,\"leafHash\":\"%s\"}",
                        lf.get("studentId"), escapeJson((String)lf.get("department")),
                        escapeJson((String)lf.get("grade")), lf.get("totalMarks"), lf.get("leafHash")
                    ));
                    if (i < leaves.size() - 1) sb.append(",");
                }
                sb.append("]}");

                sendJsonResponse(exchange, 200, sb.toString());
            } catch (Exception e) {
                sendErrorResponse(exchange, e);
            }
        }
    }

    // Handler for Term Seals Status (GET /api/v1/aetherlock/status)
    static class AetherLockStatusHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            applySecurityHeaders(exchange);
            if ("OPTIONS".equalsIgnoreCase(exchange.getRequestMethod())) {
                sendResponse(exchange, 204, "");
                return;
            }

            if (!"GET".equalsIgnoreCase(exchange.getRequestMethod())) {
                sendJsonResponse(exchange, 405, "{\"error\":\"Method Not Allowed\"}");
                return;
            }

            try {
                boolean isSealed = AetherLockService.isSystemSealed();
                List<AetherLockService.TermSeal> seals = AetherLockService.getAllSeals();
                StringBuilder sb = new StringBuilder();
                sb.append(String.format(Locale.US, "{\"isSystemSealed\":%b,\"totalSeals\":%d,\"seals\":[", isSealed, seals.size()));
                for (int i = 0; i < seals.size(); i++) {
                    sb.append(seals.get(i).toJson());
                    if (i < seals.size() - 1) sb.append(",");
                }
                sb.append("]}");
                sendJsonResponse(exchange, 200, sb.toString());
            } catch (Exception e) {
                sendErrorResponse(exchange, e);
            }
        }
    }

    // Handler for Stateless Proof Verification (POST /api/v1/aetherlock/verify-proof)
    static class AetherLockVerifyProofHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            applySecurityHeaders(exchange);
            if ("OPTIONS".equalsIgnoreCase(exchange.getRequestMethod())) {
                sendResponse(exchange, 204, "");
                return;
            }

            if (!"POST".equalsIgnoreCase(exchange.getRequestMethod()) && !"GET".equalsIgnoreCase(exchange.getRequestMethod())) {
                sendJsonResponse(exchange, 405, "{\"error\":\"Method Not Allowed\"}");
                return;
            }

            String token = "";
            if ("GET".equalsIgnoreCase(exchange.getRequestMethod())) {
                Map<String, String> params = parseQueryParams(exchange.getRequestURI().getQuery());
                token = params.getOrDefault("token", "");
            } else {
                String body = getBody(exchange);
                if (body.contains("\"token\"")) {
                    token = getJsonString(body, "token");
                }
                if (token.isEmpty()) {
                    token = body;
                }
            }

            if (token == null || token.trim().isEmpty()) {
                sendJsonResponse(exchange, 400, "{\"valid\":false,\"error\":\"No verification token provided\"}");
                return;
            }

            AetherLockService.VerificationResult result = AetherLockService.verifyProof(token);
            sendJsonResponse(exchange, 200, result.toJson());
        }
    }

    // Handler for Generating ZK Credential Badge (GET/POST /api/v1/aetherlock/generate-credential)
    static class AetherLockGenerateCredentialHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            applySecurityHeaders(exchange);
            if ("OPTIONS".equalsIgnoreCase(exchange.getRequestMethod())) {
                sendResponse(exchange, 204, "");
                return;
            }

            if (!"GET".equalsIgnoreCase(exchange.getRequestMethod()) && !"POST".equalsIgnoreCase(exchange.getRequestMethod())) {
                sendJsonResponse(exchange, 405, "{\"error\":\"Method Not Allowed\"}");
                return;
            }

            int studentId = 0;
            String path = exchange.getRequestURI().getPath();
            if (path.startsWith("/api/v1/aetherlock/generate-credential/")) {
                String suffix = path.substring("/api/v1/aetherlock/generate-credential/".length());
                if (!suffix.isEmpty()) {
                    try { studentId = Integer.parseInt(suffix); } catch (NumberFormatException ignored) {}
                }
            }

            if (studentId <= 0) {
                Map<String, String> params = parseQueryParams(exchange.getRequestURI().getQuery());
                if (params.containsKey("studentId")) {
                    studentId = Integer.parseInt(params.get("studentId"));
                } else if (params.containsKey("id")) {
                    studentId = Integer.parseInt(params.get("id"));
                } else {
                    String body = getBody(exchange);
                    if (body.contains("studentId")) {
                        studentId = getJsonInt(body, "studentId");
                    }
                }
            }

            if (studentId <= 0) {
                sendJsonResponse(exchange, 400, "{\"error\":\"Invalid or missing studentId parameter\"}");
                return;
            }

            try {
                String token = AetherLockService.generateZkCredential(studentId, repository);
                Student student = repository.getStudent(studentId);
                String json = String.format(Locale.US,
                    "{\"success\":true,\"studentId\":%d,\"studentName\":\"%s\",\"department\":\"%s\",\"token\":\"%s\",\"message\":\"AetherLock ZK Credential generated successfully\"}",
                    studentId, escapeJson(student.getName()), escapeJson(student.getDepartment()), token
                );
                sendJsonResponse(exchange, 200, json);
            } catch (StudentNotFoundException e) {
                sendJsonResponse(exchange, 404, "{\"error\":\"Student not found with ID " + studentId + "\"}");
            } catch (Exception e) {
                sendErrorResponse(exchange, e);
            }
        }
    }

    // Generic response utilities
    private static void sendJsonResponse(HttpExchange exchange, int statusCode, String jsonResponse) throws IOException {
        exchange.getResponseHeaders().set("Content-Type", "application/json");
        sendResponse(exchange, statusCode, jsonResponse);
    }

    private static void sendResponse(HttpExchange exchange, int statusCode, String response) throws IOException {
        byte[] bytes = response.getBytes("UTF-8");
        exchange.sendResponseHeaders(statusCode, bytes.length);
        try (OutputStream os = exchange.getResponseBody()) {
            os.write(bytes);
        }
    }

    private static void sendErrorResponse(HttpExchange exchange, Exception e) throws IOException {
        int status = 500;
        String errorMsg = e.getMessage();
        if (e instanceof InvalidMarksException || e instanceof InvalidAttendanceException || e instanceof DuplicateStudentException) {
            status = 400;
        } else if (e instanceof StudentNotFoundException) {
            status = 404;
        }

        String jsonResponse = String.format("{\"error\":\"%s\"}", errorMsg != null ? escapeJson(errorMsg) : "An unexpected error occurred");
        sendJsonResponse(exchange, status, jsonResponse);
    }

    private static String getBody(HttpExchange exchange) throws IOException {
        try (InputStream is = exchange.getRequestBody();
             Scanner s = new Scanner(is, "UTF-8").useDelimiter("\\A")) {
            return s.hasNext() ? s.next() : "";
        }
    }

    private static String getJsonString(String json, String key) {
        Pattern p = Pattern.compile("\"" + key + "\":\\s*\"([^\"]*)\"");
        Matcher m = p.matcher(json);
        return m.find() ? m.group(1) : "";
    }

    private static int getJsonInt(String json, String key) {
        Pattern p = Pattern.compile("\"" + key + "\":\\s*\"?(-?\\d+)\"?");
        Matcher m = p.matcher(json);
        return m.find() ? Integer.parseInt(m.group(1)) : 0;
    }

    private static double getJsonDouble(String json, String key) {
        Pattern p = Pattern.compile("\"" + key + "\":\\s*\"?(-?\\d*\\.?\\d+)\"?");
        Matcher m = p.matcher(json);
        return m.find() ? Double.parseDouble(m.group(1)) : 0.0;
    }

    private static Map<String, String> parseQueryParams(String query) {
        Map<String, String> result = new HashMap<>();
        if (query == null) return result;
        for (String param : query.split("&")) {
            String[] entry = param.split("=");
            if (entry.length > 1) {
                result.put(entry[0], entry[1]);
            } else if (entry.length > 0) {
                result.put(entry[0], "");
            }
        }
        return result;
    }

    private static String escapeJson(String s) {
        if (s == null) return "";
        return s.replace("\\", "\\\\").replace("\"", "\\\"");
    }
}
