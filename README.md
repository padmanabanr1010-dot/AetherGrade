# AetherGrade 🛡️📊

**Enterprise-Grade Student Grade Management & Cryptographic Integrity Platform**

AetherGrade is a high-performance, security-focused Student Grade Management System built in Core Java. Beyond standard grade tracking and academic analytics, AetherGrade incorporates cryptographic primitives including **Zero-Knowledge Proofs (ZKP)**, **Merkle Tree Proofs**, an **Immutable Audit Ledger (SHA-256 Hash Chain)**, and **AetherLock Term Sealing** to guarantee tamper-proof academic credentials and verifiable record integrity.

---

## 🌟 Key Features

### 1. 🔐 Cryptographic Integrity & Zero-Trust Verification
- **AetherLock Term Sealing**: Cryptographically seal academic terms using Merkle Trees (`SHA-256`) and digital signatures. Once sealed, grades cannot be modified without invalidating the seal.
- **Merkle Tree Proofs**: Generate and verify inclusion proofs for individual student grade records against the published root hash.
- **Zero-Knowledge Proofs (ZKP)**: Issue verifiable claims (e.g., verifying whether a student scored above a threshold or passed) without exposing raw marks or private data.
- **Immutable Audit Ledger**: Chain-of-custody logging utilizing SHA-256 block hashing where every student modification links to the previous hash.

### 2. 👥 Role-Based Access Control (RBAC) & Security
- **JWT-Based Authentication**: Secure token generation with HMAC-SHA256 signatures and expiration policies.
- **Password Hashing**: Secure salted SHA-256 / PBKDF2 credential storage.
- **Granular Roles**: Differentiated access for `ADMIN`, `FACULTY`, and `STUDENT`.
- **Rate Limiting & Security Headers**: Built-in sliding window rate limiting and HTTP security headers (`nosniff`, `DENY`, XSS protection).

### 3. 📈 Academic Management & Analytics
- Complete CRUD operations for student profiles, subject marks (Java, OS, Maths, DAA, CA, ML), attendance, and grades.
- Automatic computation of total marks, percentages, and letter grades.
- Real-time batch performance statistics and departmental distribution.

### 4. ⚡ Design Patterns & Architecture
- **Repository Pattern**: `StudentRepository` interface decoupled from `JdbcStudentRepository` implementation.
- **Observer Pattern**: `AttendanceObserver` and `LowAttendanceNotifier` automatically flag attendance below statutory limits (< 75%).
- **Factory Pattern**: `ReportFactory` and `CsvReportGenerator` for extensible export formats.
- **Asynchronous Processing**: Background multi-threaded executor (`ExecutorService`) for non-blocking large CSV report generation with live progress reporting.

### 5. 🎨 Modern Glassmorphic Web Dashboard
- Fully responsive, sleek UI served via embedded Java HTTP Server (`com.sun.net.httpserver.HttpServer`).
- Real-time filtering, interactive charts, cryptographic credential verification modal, and audit ledger viewer.

---

## 🛠️ Technology Stack

- **Backend**: Java 17+ (Core Java SE, `com.sun.net.httpserver`)
- **Database**: MySQL 8.0+
- **Driver**: MySQL Connector/J (`mysql-connector-j-26.7.0.jar`)
- **Frontend**: HTML5, Vanilla JavaScript (ES6+), Glassmorphic CSS3
- **Security**: SHA-256, HMAC-SHA256, Merkle Trees, ZKP Commitment Schemes

---

## 📂 Project Structure

```text
AetherGrade/
├── lib/
│   └── mysql-connector-j-26.7.0.jar   # MySQL JDBC Driver
├── src/
│   ├── audit/                         # Cryptographic Audit Ledger & Logger
│   │   ├── AuditLedgerUtil.java
│   │   └── AuditLogger.java
│   ├── database/                      # Connection provider & DAO
│   │   ├── DBConnection.java
│   │   └── StudentDAO.java
│   ├── exceptions/                    # Custom Domain Exceptions
│   │   ├── DuplicateStudentException.java
│   │   ├── InvalidAttendanceException.java
│   │   ├── InvalidMarksException.java
│   │   └── StudentNotFoundException.java
│   ├── factory/                       # Report generation factory
│   │   ├── CsvReportGenerator.java
│   │   ├── ReportFactory.java
│   │   └── ReportGenerator.java
│   ├── interfaces/                    # Domain interfaces
│   │   ├── Attendance.java
│   │   └── GradeCalculator.java
│   ├── main/                          # Entry point
│   │   └── App.java
│   ├── model/                         # Domain models (Student, AcademicStudent)
│   │   ├── AcademicStudent.java
│   │   └── Student.java
│   ├── observer/                      # Observer pattern (Low attendance alerts)
│   │   ├── AttendanceObserver.java
│   │   └── LowAttendanceNotifier.java
│   ├── repository/                    # Repository abstraction layer
│   │   ├── JdbcStudentRepository.java
│   │   └── StudentRepository.java
│   ├── security/                      # Cryptographic & Auth services
│   │   ├── AetherLockService.java
│   │   ├── AuthService.java
│   │   ├── CryptoUtil.java
│   │   ├── JwtUtil.java
│   │   ├── MerkleTree.java
│   │   ├── PasswordHasher.java
│   │   ├── RateLimiter.java
│   │   └── ZkpVerificationUtil.java
│   ├── test/                          # Unit and integration test runner
│   │   └── TestRunner.java
│   └── web/                           # Embedded HTTP server & API handlers
│       └── WebServer.java
├── webroot/                           # Static Web Application frontend
│   ├── app.js
│   ├── index.html
│   └── style.css
├── schema.sql                         # Database DDL schema
├── sources.txt                        # Compilation sources manifest
├── .gitignore
└── README.md
```

---

## 🚀 Getting Started

### Prerequisites

1. **Java Development Kit (JDK 17 or higher)**
   ```bash
   java -version
   javac -version
   ```
2. **MySQL Server (8.0+)**

---

### 1. Database Setup

1. Start your MySQL service.
2. Log into MySQL and execute the `schema.sql` script:
   ```bash
   mysql -u root -p < schema.sql
   ```
3. Update your database connection credentials if needed in [src/database/DBConnection.java](file:///c:/Users/kisho/OneDrive/Documents/Java%20Project/src/database/DBConnection.java):
   ```java
   static final String URL = "jdbc:mysql://localhost:3306/studentgrademanager";
   static final String USER = "root";
   static final String PASSWORD = "your_mysql_password";
   ```

---

### 2. Compile the Project

Compile the Java source files into the `out` directory:

#### **PowerShell (Windows)**:
```powershell
javac -cp "lib/*" -d out '@sources.txt'
```

#### **Command Prompt (Windows)**:
```cmd
javac -cp "lib/*" -d out @sources.txt
```

#### **Linux / macOS**:
```bash
javac -cp "lib/*" -d out @sources.txt
```

---

### 3. Run the Application

Launch the embedded server application:

#### **Windows**:
```powershell
java -cp "out;lib/*" main.App
```

#### **Linux / macOS**:
```bash
java -cp "out:lib/*" main.App
```

Once running, access the dashboard in your browser:
👉 **[http://localhost:8080](http://localhost:8080)**

---

## 🔑 Default Login Credentials

The system seeds the following default accounts on startup:

| Role | Username | Password | Access Level |
|---|---|---|---|
| **Administrator** | `admin` | `admin123` | Full access (CRUD, Term Sealing, Audit Ledger) |
| **Faculty** | `faculty` | `faculty123` | Grade entry, reports, student viewing |

---

## 📡 REST API Reference

| Endpoint | Method | Description |
|---|---|---|
| `/api/auth/login` | `POST` | Authenticate user and receive JWT bearer token |
| `/api/auth/me` | `GET` | Retrieve session information for current token |
| `/api/students` | `GET`, `POST`, `PUT`, `DELETE` | Manage student records |
| `/api/stats` | `GET` | Get class statistics and analytics |
| `/api/report/generate` | `POST` | Trigger asynchronous background CSV export |
| `/api/report/status` | `GET` | Poll background report progress (`0-100%`) |
| `/api/report/download` | `GET` | Download generated CSV report |
| `/api/v1/audit/ledger` | `GET` | Inspect cryptographic audit trail |
| `/api/v1/audit/verify` | `GET` | Validate SHA-256 chain integrity |
| `/api/v1/aetherlock/seal-term` | `POST` | Seal academic term with Merkle Root |
| `/api/v1/aetherlock/verify-proof` | `POST` | Verify Merkle inclusion proof for a record |
| `/api/v1/verify-claim` | `POST` | Zero-Knowledge proof claim verification |

---

## 🔒 Security Best Practices

- Change default MySQL and administrator passwords prior to production deployments.
- Deploy behind a reverse proxy (e.g., NGINX / Caddy) with TLS/HTTPS enabled for production environments.

---

## 📄 License

This project is licensed under the MIT License.
