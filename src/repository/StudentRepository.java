package repository;

import model.Student;
import exceptions.DuplicateStudentException;
import exceptions.StudentNotFoundException;

import java.sql.SQLException;
import java.util.List;
import java.util.Map;

public interface StudentRepository {
    void addStudent(Student student) throws DuplicateStudentException, SQLException;
    void updateStudent(Student student) throws StudentNotFoundException, SQLException;
    void updateStudentMarks(int studentId, int javaMarks, int osMarks, int mathsMarks, int daaMarks, int caMarks, int mlMarks) throws StudentNotFoundException, SQLException;
    void deleteStudent(int studentId) throws StudentNotFoundException, SQLException;
    Student getStudent(int studentId) throws StudentNotFoundException, SQLException;
    List<Student> getAllStudents() throws SQLException;
    boolean studentExists(int studentId) throws SQLException;
    List<Student> getAllStudentsSortedByName() throws SQLException;
    List<Student> getAllStudentsSortedByPercentage() throws SQLException;
    Map<String, Map<String, Object>> getDepartmentStatistics() throws SQLException;
}
