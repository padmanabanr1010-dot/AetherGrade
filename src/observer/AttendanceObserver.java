package observer;

import model.Student;

public interface AttendanceObserver {
    void onLowAttendanceDetected(Student student);
}
