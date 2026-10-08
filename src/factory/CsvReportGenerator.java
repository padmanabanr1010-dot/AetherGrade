package factory;

import model.Student;
import java.util.List;

public class CsvReportGenerator implements ReportGenerator {

    @Override
    public String generateReport(List<Student> students) {
        StringBuilder csv = new StringBuilder();
        csv.append("Student ID,Name,Department,Year,Java,OS,Maths,DAA,CA,ML,Total,Percentage,Grade,Attendance %,Exam Status\n");

        for (Student s : students) {
            String examStatus = (s.getAttendance() >= 75) ? "ELIGIBLE" : "NOT ELIGIBLE";
            csv.append(String.format(
                "%d,\"%s\",\"%s\",%d,%d,%d,%d,%d,%d,%d,%d,%.2f,%s,%.2f,%s\n",
                s.getStudentId(),
                escapeCsv(s.getName()),
                escapeCsv(s.getDepartment()),
                s.getYear(),
                s.getJavaMarks(),
                s.getOsMarks(),
                s.getMathsMarks(),
                s.getDaaMarks(),
                s.getCaMarks(),
                s.getMlMarks(),
                s.getTotal(),
                s.getPercentage(),
                s.getGrade(),
                s.getAttendance(),
                examStatus
            ));
        }

        return csv.toString();
    }

    @Override
    public String getMimeType() {
        return "text/csv";
    }

    @Override
    public String getFileExtension() {
        return "csv";
    }

    private String escapeCsv(String input) {
        if (input == null) return "";
        return input.replace("\"", "\"\"");
    }
}
