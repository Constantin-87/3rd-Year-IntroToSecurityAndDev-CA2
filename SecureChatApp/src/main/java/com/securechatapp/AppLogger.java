package com.securechatapp;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.util.Properties;
import java.util.logging.FileHandler;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.logging.SimpleFormatter;

public class AppLogger {

    private static final Logger logger = Logger.getLogger("AppLogger");
    private static FileHandler fileHandler;

    static {
        initializeLogger();
    }

    private static void initializeLogger() {
        try {
            Properties properties = new Properties();
            try ( InputStream input = AppLogger.class.getClassLoader().getResourceAsStream("config.properties")) {
                if (input == null) {
                    throw new IOException("Unable to find config.properties");
                }
                properties.load(input);
            }

            // Get the relative log file path from the properties file or use a default value
            String logFilePath = properties.getProperty("log.filepath", "./AppLog.log");

            // Resolve the path relative to the current working directory
            File logFile = new File(logFilePath).getAbsoluteFile();

            // Ensure log directory exists
            File logDir = logFile.getParentFile();
            if (!logDir.exists() && !logDir.mkdirs()) {
                System.err.println("Failed to create log directories for path: " + logDir.getAbsolutePath());
                return;
            }

            // Create a FileHandler that appends to the specified log file
            fileHandler = new FileHandler(logFile.getAbsolutePath(), true);
            logger.addHandler(fileHandler);

            SimpleFormatter formatter = new SimpleFormatter();
            fileHandler.setFormatter(formatter);

            logger.log(Level.INFO, "Logger initialized and log file is located at: {0}", logFile.getAbsolutePath());
        } catch (IOException e) {
            System.err.println("Could not initialize log file: " + e.getMessage());
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
}
