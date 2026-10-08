package main;

import web.WebServer;

public class App {
    public static void main(String[] args) {
        try {
            System.out.println("Starting Student Grade Management System Web Application...");
            WebServer.start();
        } catch (Exception e) {
            System.err.println("Fatal Error during Web Server startup: " + e.getMessage());
            e.printStackTrace();
        }
    }
}
