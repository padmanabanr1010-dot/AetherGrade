package factory;

public class ReportFactory {

    public enum ReportType {
        CSV
    }

    public static ReportGenerator getReportGenerator(ReportType type) {
        if (type == ReportType.CSV) {
            return new CsvReportGenerator();
        }
        throw new IllegalArgumentException("Unsupported report type: " + type);
    }

    public static ReportGenerator getReportGenerator(String format) {
        if (format == null || format.trim().isEmpty() || "csv".equalsIgnoreCase(format.trim())) {
            return new CsvReportGenerator();
        }
        throw new IllegalArgumentException("Unsupported report format: " + format);
    }
}
