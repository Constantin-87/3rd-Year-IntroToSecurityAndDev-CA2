package com.securechatapp;

import java.io.IOException;
import java.util.logging.FileHandler;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.logging.SimpleFormatter;

public class AppLogger {

    private static final Logger logger = Logger.getLogger("AppLogger");
    private static FileHandler fileHandler;

    static {
        try {
            String logFilePath = "C:\\Users\\Alex\\Desktop\\Scoala\\3RD year\\Security fundamentals and Development\\CA1\\SecureChatApp\\AppLog.log";

            // Set a large limit for the log file size (e.g., 100 MB) and 1 file count
            int limit = 100000000; // 100 MB
            int fileCount = 1;
            boolean append = true;

            fileHandler = new FileHandler(logFilePath, limit, fileCount, append);
            logger.setLevel(Level.ALL);
            SimpleFormatter formatter = new SimpleFormatter();
            fileHandler.setFormatter(formatter);
            logger.addHandler(fileHandler);

            logger.info("Logger initialized and log file is located at: " + logFilePath);
        } catch (IOException e) {
            System.err.println("Error occurred in FileHandler.");
            e.printStackTrace();
            throw new RuntimeException("Failed to initialize logger", e);
        }
    }

    // To prevent instantiation
    private AppLogger() {
    }

    public static void log(Level level, String message) {
        logger.log(level, message);
    }

    public static void info(String message) {
        logger.info(message);
    }

    public static void severe(String message) {
        logger.severe(message);
    }

    public static void warning(String message) {
        logger.warning(message);
    }

    public static void fine(String message) {
        logger.fine(message);
    }

    // Add other methods if required
}
