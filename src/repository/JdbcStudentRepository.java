package repository;

import database.StudentDAO;
import exceptions.DuplicateStudentException;
import exceptions.StudentNotFoundException;
import model.Student;

import java.sql.SQLException;
import java.util.List;
import java.util.Map;

public class JdbcStudentRepository implements StudentRepository {
    private final StudentDAO dao;

    public JdbcStudentRepository() {
        this.dao = new StudentDAO();
    }

    public JdbcStudentRepository(StudentDAO dao) {
        this.dao = dao;
    }

    @Override
    public void addStudent(Student student) throws DuplicateStudentException, SQLException {
        dao.addStudent(student);
    }

    @Override
    public void updateStudent(Student student) throws StudentNotFoundException, SQLException {
        dao.updateStudent(student);
    }

    @Override
    public void updateStudentMarks(int studentId, int javaMarks, int osMarks, int mathsMarks, int daaMarks, int caMarks, int mlMarks) throws StudentNotFoundException, SQLException {
        dao.updateStudentMarks(studentId, javaMarks, osMarks, mathsMarks, daaMarks, caMarks, mlMarks);
    }

    @Override
    public void deleteStudent(int studentId) throws StudentNotFoundException, SQLException {
        dao.deleteStudent(studentId);
    }

    @Override
    public Student getStudent(int studentId) throws StudentNotFoundException, SQLException {
        return dao.getStudent(studentId);
    }

    @Override
    public List<Student> getAllStudents() throws SQLException {
        return dao.getAllStudents();
    }

    @Override
    public boolean studentExists(int studentId) throws SQLException {
        return dao.studentExists(studentId);
    }

    @Override
    public List<Student> getAllStudentsSortedByName() throws SQLException {
        return dao.getAllStudentsSortedByName();
    }

    @Override
    public List<Student> getAllStudentsSortedByPercentage() throws SQLException {
        return dao.getAllStudentsSortedByPercentage();
    }

    @Override
    public Map<String, Map<String, Object>> getDepartmentStatistics() throws SQLException {
        return dao.getDepartmentStatistics();
    }
}
