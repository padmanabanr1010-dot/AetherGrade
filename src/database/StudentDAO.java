package database;

import java.sql.*;
import java.util.*;
import java.util.stream.Collectors;
import model.AcademicStudent;
import model.Student;
import repository.StudentRepository;
import exceptions.DuplicateStudentException;
import exceptions.StudentNotFoundException;
import audit.AuditLogger;
import audit.AuditLedgerUtil;
import security.AetherLockService;

public class StudentDAO implements StudentRepository {

    public StudentDAO() {
        ensureSchemaUpdated();
        populateDefaultNewSubjectMarks();
    }

    private void ensureSchemaUpdated() {
        try (Connection con = DBConnection.getConnection()) {
            if (con == null) return;
            try (Statement st = con.createStatement()) {
                st.executeUpdate("ALTER TABLE students ADD COLUMN os_marks INT NOT NULL DEFAULT 0 AFTER java_marks");
            } catch (SQLException ignored) {}
            try (Statement st = con.createStatement()) {
                st.executeUpdate("ALTER TABLE students ADD COLUMN maths_marks INT NOT NULL DEFAULT 0 AFTER os_marks");
            } catch (SQLException ignored) {}
            try (Statement st = con.createStatement()) {
                st.executeUpdate("ALTER TABLE students ADD COLUMN daa_marks INT NOT NULL DEFAULT 0 AFTER maths_marks");
            } catch (SQLException ignored) {}
            try (Statement st = con.createStatement()) {
                st.executeUpdate("ALTER TABLE students ADD COLUMN ca_marks INT NOT NULL DEFAULT 0 AFTER daa_marks");
            } catch (SQLException ignored) {}
            try (Statement st = con.createStatement()) {
                st.executeUpdate("ALTER TABLE students ADD COLUMN ml_marks INT NOT NULL DEFAULT 0 AFTER ca_marks");
            } catch (SQLException ignored) {}
            AuditLedgerUtil.ensureTableExists(con);
        } catch (Exception e) {
            System.err.println("Schema auto-migration notice: " + e.getMessage());
        }
    }

    private void populateDefaultNewSubjectMarks() {
        try {
            List<Student> students = getAllStudents();
            Random rand = new Random();
            for (Student s : students) {
                if (s.getDaaMarks() == 0 || s.getCaMarks() == 0 || s.getMlMarks() == 0) {
                    if (s.getDaaMarks() == 0) s.setDaaMarks(rand.nextInt(36) + 60);
                    if (s.getCaMarks() == 0) s.setCaMarks(rand.nextInt(36) + 60);
                    if (s.getMlMarks() == 0) s.setMlMarks(rand.nextInt(36) + 60);
                    updateStudent(s);
                }
            }
        } catch (Exception ignored) {}
    }

    @Override
    public void addStudent(Student s) throws DuplicateStudentException, SQLException {
        if (studentExists(s.getStudentId())) {
            throw new DuplicateStudentException("Student with ID " + s.getStudentId() + " already exists.");
        }

        String sql = "INSERT INTO students (student_id, name, department, year, java_marks, os_marks, maths_marks, daa_marks, ca_marks, ml_marks, total, percentage, grade, attendance) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)";
        try (Connection con = DBConnection.getConnection();
             PreparedStatement ps = con.prepareStatement(sql)) {
            
            ps.setInt(1, s.getStudentId());
            ps.setString(2, s.getName());
            ps.setString(3, s.getDepartment());
            ps.setInt(4, s.getYear());
            ps.setInt(5, s.getJavaMarks());
            ps.setInt(6, s.getOsMarks());
            ps.setInt(7, s.getMathsMarks());
            ps.setInt(8, s.getDaaMarks());
            ps.setInt(9, s.getCaMarks());
            ps.setInt(10, s.getMlMarks());
            ps.setInt(11, s.getTotal());
            ps.setDouble(12, s.getPercentage());
            ps.setString(13, s.getGrade());
            ps.setDouble(14, s.getAttendance());

            ps.executeUpdate();
            
            AuditLedgerUtil.appendBlock(con, "SYSTEM", "STUDENT_ENROLL", s.getStudentId(), s.toJson());
        }
    }

    @Override
    public void updateStudent(Student s) throws StudentNotFoundException, SQLException {
        if (!studentExists(s.getStudentId())) {
            throw new StudentNotFoundException("Student with ID " + s.getStudentId() + " not found.");
        }

        if (AetherLockService.isStudentLocked(s.getStudentId())) {
            throw new SecurityException("AetherLock Immutability Enforcement: Academic term is cryptographically sealed with Merkle Tree root. Student record updates are blocked.");
        }

        String sql = "UPDATE students SET name = ?, department = ?, year = ?, java_marks = ?, os_marks = ?, maths_marks = ?, daa_marks = ?, ca_marks = ?, ml_marks = ?, total = ?, percentage = ?, grade = ?, attendance = ? WHERE student_id = ?";
        try (Connection con = DBConnection.getConnection();
             PreparedStatement ps = con.prepareStatement(sql)) {
            
            ps.setString(1, s.getName());
            ps.setString(2, s.getDepartment());
            ps.setInt(3, s.getYear());
            ps.setInt(4, s.getJavaMarks());
            ps.setInt(5, s.getOsMarks());
            ps.setInt(6, s.getMathsMarks());
            ps.setInt(7, s.getDaaMarks());
            ps.setInt(8, s.getCaMarks());
            ps.setInt(9, s.getMlMarks());
            ps.setInt(10, s.getTotal());
            ps.setDouble(11, s.getPercentage());
            ps.setString(12, s.getGrade());
            ps.setDouble(13, s.getAttendance());
            ps.setInt(14, s.getStudentId());

            ps.executeUpdate();

            AuditLedgerUtil.appendBlock(con, "SYSTEM", "STUDENT_UPDATE", s.getStudentId(), s.toJson());
        }
    }

    @Override
    public void updateStudentMarks(int studentId, int javaMarks, int osMarks, int mathsMarks,
                                   int daaMarks, int caMarks, int mlMarks) throws StudentNotFoundException, SQLException {
        Student s = getStudent(studentId);
        s.setJavaMarks(javaMarks);
        s.setOsMarks(osMarks);
        s.setMathsMarks(mathsMarks);
        s.setDaaMarks(daaMarks);
        s.setCaMarks(caMarks);
        s.setMlMarks(mlMarks);
        updateStudent(s);
    }

    @Override
    public void deleteStudent(int studentId) throws StudentNotFoundException, SQLException {
        if (AetherLockService.isStudentLocked(studentId)) {
            throw new SecurityException("AetherLock Immutability Enforcement: Academic term is cryptographically sealed with Merkle Tree root. Student deletion is blocked.");
        }

        String sql = "DELETE FROM students WHERE student_id = ?";
        try (Connection con = DBConnection.getConnection();
             PreparedStatement ps = con.prepareStatement(sql)) {
            
            ps.setInt(1, studentId);
            int affected = ps.executeUpdate();
            if (affected == 0) {
                throw new StudentNotFoundException("Student with ID " + studentId + " not found.");
            }
            AuditLedgerUtil.appendBlock(con, "SYSTEM", "STUDENT_DELETE", studentId, "Deleted Student ID: " + studentId);
        }
    }

    @Override
    public Student getStudent(int studentId) throws StudentNotFoundException, SQLException {
        String sql = "SELECT * FROM students WHERE student_id = ?";
        try (Connection con = DBConnection.getConnection();
             PreparedStatement ps = con.prepareStatement(sql)) {
            
            ps.setInt(1, studentId);
            try (ResultSet rs = ps.executeQuery()) {
                if (rs.next()) {
                    return new AcademicStudent(
                        rs.getInt("student_id"),
                        rs.getString("name"),
                        rs.getString("department"),
                        rs.getInt("year"),
                        rs.getInt("java_marks"),
                        rs.getInt("os_marks"),
                        rs.getInt("maths_marks"),
                        getSafeInt(rs, "daa_marks"),
                        getSafeInt(rs, "ca_marks"),
                        getSafeInt(rs, "ml_marks"),
                        rs.getDouble("attendance")
                    );
                } else {
                    throw new StudentNotFoundException("Student with ID " + studentId + " not found.");
                }
            }
        }
    }

    @Override
    public List<Student> getAllStudents() throws SQLException {
        List<Student> list = new ArrayList<>();
        String sql = "SELECT * FROM students";
        try (Connection con = DBConnection.getConnection();
             Statement st = con.createStatement();
             ResultSet rs = st.executeQuery(sql)) {
            
            while (rs.next()) {
                list.add(new AcademicStudent(
                    rs.getInt("student_id"),
                    rs.getString("name"),
                    rs.getString("department"),
                    rs.getInt("year"),
                    rs.getInt("java_marks"),
                    rs.getInt("os_marks"),
                    rs.getInt("maths_marks"),
                    getSafeInt(rs, "daa_marks"),
                    getSafeInt(rs, "ca_marks"),
                    getSafeInt(rs, "ml_marks"),
                    rs.getDouble("attendance")
                ));
            }
        }
        return list;
    }

    private int getSafeInt(ResultSet rs, String colName) {
        try {
            return rs.getInt(colName);
        } catch (SQLException e) {
            return 0;
        }
    }

    @Override
    public boolean studentExists(int studentId) throws SQLException {
        String sql = "SELECT 1 FROM students WHERE student_id = ?";
        try (Connection con = DBConnection.getConnection();
             PreparedStatement ps = con.prepareStatement(sql)) {
            ps.setInt(1, studentId);
            try (ResultSet rs = ps.executeQuery()) {
                return rs.next();
            }
        }
    }

    // Refactored to use Java Streams API
    @Override
    public List<Student> getAllStudentsSortedByName() throws SQLException {
        return getAllStudents().stream()
                .sorted(Comparator.comparing(Student::getName, String.CASE_INSENSITIVE_ORDER))
                .collect(Collectors.toList());
    }

    // Refactored to use Java Streams API
    @Override
    public List<Student> getAllStudentsSortedByPercentage() throws SQLException {
        return getAllStudents().stream()
                .sorted(Comparator.comparingDouble(Student::getPercentage).reversed())
                .collect(Collectors.toList());
    }

    // Refactored to use Java Streams API groupingBy and collectors
    @Override
    public Map<String, Map<String, Object>> getDepartmentStatistics() throws SQLException {
        List<Student> students = getAllStudents();
        
        Map<String, List<Student>> grouped = students.stream()
                .collect(Collectors.groupingBy(Student::getDepartment));

        return grouped.entrySet().stream()
                .collect(Collectors.toMap(
                    Map.Entry::getKey,
                    entry -> {
                        List<Student> deptStudents = entry.getValue();
                        double avgPct = deptStudents.stream()
                                .mapToDouble(Student::getPercentage)
                                .average()
                                .orElse(0.0);

                        long passCount = deptStudents.stream()
                                .filter(s -> !"FAIL".equals(s.getGrade()))
                                .count();

                        double passRate = deptStudents.isEmpty() ? 0.0 : ((double) passCount / deptStudents.size()) * 100.0;

                        Map<String, Object> stats = new HashMap<>();
                        stats.put("studentCount", deptStudents.size());
                        stats.put("averagePercentage", avgPct);
                        stats.put("passRate", passRate);
                        return stats;
                    }
                ));
    }
}
