-- Database Setup for Student Grade Management System

CREATE DATABASE IF NOT EXISTS studentgrademanager;
USE studentgrademanager;

CREATE TABLE IF NOT EXISTS students (
    student_id INT PRIMARY KEY,
    name VARCHAR(100) NOT NULL,
    department VARCHAR(50) NOT NULL,
    year INT NOT NULL,
    java_marks INT NOT NULL,
    os_marks INT NOT NULL,
    maths_marks INT NOT NULL,
    daa_marks INT NOT NULL DEFAULT 0,
    ca_marks INT NOT NULL DEFAULT 0,
    ml_marks INT NOT NULL DEFAULT 0,
    total INT NOT NULL,
    percentage DOUBLE NOT NULL,
    grade VARCHAR(10) NOT NULL,
    attendance DOUBLE NOT NULL
);

CREATE TABLE IF NOT EXISTS users (
    username VARCHAR(50) PRIMARY KEY,
    password_hash VARCHAR(255) NOT NULL,
    role VARCHAR(20) NOT NULL,
    student_id INT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (student_id) REFERENCES students(student_id) ON DELETE SET NULL
);

CREATE TABLE IF NOT EXISTS audit_logs (
    log_id INT AUTO_INCREMENT PRIMARY KEY,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    username VARCHAR(50),
    role VARCHAR(20),
    action VARCHAR(50) NOT NULL,
    resource VARCHAR(100),
    ip_address VARCHAR(45),
    status VARCHAR(20) NOT NULL,
    details TEXT
);

CREATE TABLE IF NOT EXISTS audit_ledger (
    id INT AUTO_INCREMENT PRIMARY KEY,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    actor_id VARCHAR(50) NOT NULL,
    action_type VARCHAR(50) NOT NULL,
    record_id INT NOT NULL,
    data_payload TEXT NOT NULL,
    previous_hash VARCHAR(64) NOT NULL,
    current_hash VARCHAR(64) NOT NULL
);

CREATE TABLE IF NOT EXISTS term_seals (
    seal_id VARCHAR(36) PRIMARY KEY,
    term_id VARCHAR(50) NOT NULL,
    merkle_root VARCHAR(64) NOT NULL,
    locked_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    signature TEXT NOT NULL,
    is_sealed BOOLEAN NOT NULL DEFAULT TRUE,
    student_count INT NOT NULL DEFAULT 0,
    actor_id VARCHAR(50) NOT NULL,
    salt VARCHAR(64) NOT NULL
);

