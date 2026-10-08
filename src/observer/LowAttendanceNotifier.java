package observer;

import model.Student;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;

public class LowAttendanceNotifier {
    private static final List<AttendanceObserver> observers = new CopyOnWriteArrayList<>();
    private static final List<String> alertLog = Collections.synchronizedList(new ArrayList<>());

    public static void registerObserver(AttendanceObserver observer) {
        observers.add(observer);
    }

    public static void checkAndNotify(Student student) {
        if (student != null && student.getAttendance() < 75.0) {
            String alert = String.format(
                "[LOW ATTENDANCE WARNING] Student ID: %d, Name: %s (%s, Year %d) has attendance %.2f%% (< 75%% threshold). Status: Ineligible for exams.",
                student.getStudentId(), student.getName(), student.getDepartment(), student.getYear(), student.getAttendance()
            );
            
            alertLog.add(alert);
            System.err.println(alert);

            for (AttendanceObserver observer : observers) {
                try {
                    observer.onLowAttendanceDetected(student);
                } catch (Exception e) {
                    System.err.println("Error notifying observer: " + e.getMessage());
                }
            }
        }
    }

    public static List<String> getRecentAlerts() {
        return new ArrayList<>(alertLog);
    }
}
