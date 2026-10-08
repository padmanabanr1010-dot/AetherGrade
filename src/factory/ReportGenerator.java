package factory;

import model.Student;
import java.util.List;

public interface ReportGenerator {
    String generateReport(List<Student> students);
    String getMimeType();
    String getFileExtension();
}
