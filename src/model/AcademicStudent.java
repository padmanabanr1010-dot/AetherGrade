package model;

import interfaces.Attendance;
import interfaces.GradeCalculator;

public class AcademicStudent extends Student implements GradeCalculator, Attendance {

    public AcademicStudent(int studentId, String name, String department, int year,
                           int javaMarks, int osMarks, int mathsMarks,
                           int daaMarks, int caMarks, int mlMarks, double attendance) {
        super(studentId, name, department, year, javaMarks, osMarks, mathsMarks, daaMarks, caMarks, mlMarks, attendance);
    }

    @Override
    public void displayGrade() {
        System.out.println("\n----- Grade Details -----");
        System.out.println("Student Name : " + getName());
        System.out.println("Percentage   : " + getPercentage());
        System.out.println("Grade        : " + getGrade());
    }

    @Override
    public void displayAttendanceStatus() {
        System.out.println("\n----- Attendance -----");
        System.out.println("Attendance : " + getAttendance() + "%");
        if (getAttendance() >= 75) {
            System.out.println("Status : Eligible for Exam");
        } else {
            System.out.println("Status : Not Eligible for Exam");
        }
    }

    public boolean isEligibleForExam() {
        return getAttendance() >= 75;
    }
}
