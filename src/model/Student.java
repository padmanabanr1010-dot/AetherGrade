package model;

public class Student {
    private int studentId;
    private String name;
    private String department;
    private int year;
    private int javaMarks;
    private int osMarks;
    private int mathsMarks;
    private int daaMarks;
    private int caMarks;
    private int mlMarks;
    private int total;
    private double percentage;
    private String grade;
    private double attendance;

    public Student() {}

    public Student(int studentId, String name, String department, int year,
                   int javaMarks, int osMarks, int mathsMarks,
                   int daaMarks, int caMarks, int mlMarks, double attendance) {
        this.studentId = studentId;
        this.name = name;
        this.department = department;
        this.year = year;
        this.javaMarks = javaMarks;
        this.osMarks = osMarks;
        this.mathsMarks = mathsMarks;
        this.daaMarks = daaMarks;
        this.caMarks = caMarks;
        this.mlMarks = mlMarks;
        this.attendance = attendance;
        calculateResult();
    }

    public void calculateResult() {
        this.total = javaMarks + osMarks + mathsMarks + daaMarks + caMarks + mlMarks;
        this.percentage = this.total / 6.0;
        if (this.percentage >= 90) {
            this.grade = "O";
        } else if (this.percentage >= 80) {
            this.grade = "A+";
        } else if (this.percentage >= 70) {
            this.grade = "A";
        } else if (this.percentage >= 60) {
            this.grade = "B";
        } else if (this.percentage >= 50) {
            this.grade = "C";
        } else {
            this.grade = "FAIL";
        }
    }

    // Getters and Setters
    public int getStudentId() { return studentId; }
    public void setStudentId(int studentId) { this.studentId = studentId; }

    public String getName() { return name; }
    public void setName(String name) { this.name = name; }

    public String getDepartment() { return department; }
    public void setDepartment(String department) { this.department = department; }

    public int getYear() { return year; }
    public void setYear(int year) { this.year = year; }

    public int getJavaMarks() { return javaMarks; }
    public void setJavaMarks(int javaMarks) { this.javaMarks = javaMarks; calculateResult(); }

    public int getOsMarks() { return osMarks; }
    public void setOsMarks(int osMarks) { this.osMarks = osMarks; calculateResult(); }

    public int getMathsMarks() { return mathsMarks; }
    public void setMathsMarks(int mathsMarks) { this.mathsMarks = mathsMarks; calculateResult(); }

    public int getDaaMarks() { return daaMarks; }
    public void setDaaMarks(int daaMarks) { this.daaMarks = daaMarks; calculateResult(); }

    public int getCaMarks() { return caMarks; }
    public void setCaMarks(int caMarks) { this.caMarks = caMarks; calculateResult(); }

    public int getMlMarks() { return mlMarks; }
    public void setMlMarks(int mlMarks) { this.mlMarks = mlMarks; calculateResult(); }

    public int getTotal() { return total; }
    public double getPercentage() { return percentage; }
    public String getGrade() { return grade; }

    public double getAttendance() { return attendance; }
    public void setAttendance(double attendance) { this.attendance = attendance; }

    public String toJson() {
        return String.format(
            java.util.Locale.US,
            "{\"studentId\":%d,\"name\":\"%s\",\"department\":\"%s\",\"year\":%d,\"javaMarks\":%d,\"osMarks\":%d,\"mathsMarks\":%d,\"daaMarks\":%d,\"caMarks\":%d,\"mlMarks\":%d,\"total\":%d,\"percentage\":%.2f,\"grade\":\"%s\",\"attendance\":%.2f}",
            studentId, escapeJson(name), escapeJson(department), year, javaMarks, osMarks, mathsMarks, daaMarks, caMarks, mlMarks, total, percentage, grade, attendance
        );
    }

    private String escapeJson(String s) {
        if (s == null) return "";
        return s.replace("\\", "\\\\")
                .replace("\"", "\\\"")
                .replace("\b", "\\b")
                .replace("\f", "\\f")
                .replace("\n", "\\n")
                .replace("\r", "\\r")
                .replace("\t", "\\t");
    }
}
