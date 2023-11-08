package com.securechatapp;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.X509EncodedKeySpec;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.logging.Level;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;
import javax.crypto.spec.SecretKeySpec;
import org.mindrot.jbcrypt.BCrypt;

public class DatabaseManager {

    /*
    private static DataSource dataSource;

    static {
        Properties dbProps = new Properties();
        try (InputStream is = DatabaseManager.class.getResourceAsStream("config.properties")) {
            dbProps.load(is);

            HikariConfig config = new HikariConfig();
            config.setJdbcUrl(dbProps.getProperty("db.url"));
            config.setUsername(dbProps.getProperty("db.user"));
            config.setPassword(dbProps.getProperty("db.password"));
            dataSource = new HikariDataSource(config);
        } catch (IOException e) {
            throw new ExceptionInInitializerError("Failed to load database properties.");
        }
    }
    
    public static Connection getConnection() throws SQLException {
        return dataSource.getConnection();
    }
     */
    // Database connection details
    private static final String DATABASE_URL = "jdbc:mysql://localhost:3306/securechatapp";
    private static final String DATABASE_USER = "constantin";
    private static final String DATABASE_PASSWORD = "password";

    static {
        try {
            // This will load the MySQL driver, each DB has its own driver
            Class.forName("com.mysql.cj.jdbc.Driver");
        } catch (ClassNotFoundException e) {
            AppLogger.severe("MySQL driver not found: " + e.getMessage());
        }
    }

    public static Connection getConnection() throws SQLException {
        try {
            Connection connection = DriverManager.getConnection(DATABASE_URL, DATABASE_USER, DATABASE_PASSWORD);
            return connection;
        } catch (SQLException e) {
            AppLogger.log(Level.SEVERE, "Database connection failed: " + e.getMessage());
            throw e;
        }
    }

    public static int registerUser(String username, String hashedPassword, String salt, String publicKey) throws SQLException {
        // Input validation
        if (username == null || username.trim().isEmpty()) {
            throw new IllegalArgumentException("Username cannot be null or empty.");
        }
        if (hashedPassword == null || hashedPassword.trim().isEmpty()) {
            throw new IllegalArgumentException("Hashed password cannot be null or empty.");
        }
        if (salt == null || salt.trim().isEmpty()) {
            throw new IllegalArgumentException("Salt cannot be null or empty.");
        }
        if (publicKey == null || publicKey.trim().isEmpty()) {
            throw new IllegalArgumentException("Public key cannot be null or empty.");
        }

        // SQL query to insert a new user with the username, hashed password, salt, and public key
        String insertQuery = "INSERT INTO users (username, hash, salt, public_key) VALUES (?, ?, ?, ?)";
        try ( Connection conn = getConnection();  PreparedStatement preparedStatement = conn.prepareStatement(insertQuery, Statement.RETURN_GENERATED_KEYS)) {
            preparedStatement.setString(1, username);
            preparedStatement.setString(2, hashedPassword);
            preparedStatement.setString(3, salt);
            preparedStatement.setString(4, publicKey); // Save the public key
            AppLogger.info("Storing public key for user " + username + ": " + publicKey); // Log the public key

            int rowsAffected = preparedStatement.executeUpdate();
            if (rowsAffected > 0) {
                AppLogger.info("User registered successfully: " + username);
                try ( ResultSet generatedKeys = preparedStatement.getGeneratedKeys()) {
                    if (generatedKeys.next()) {
                        return generatedKeys.getInt(1); // Return the generated ID
                    } else {
                        throw new SQLException("Creating user failed, no ID obtained.");
                    }
                }
            } else {
                AppLogger.warning("User registration failed: " + username);
                return -1; // Indicate failure
            }
        } catch (SQLException e) {
            AppLogger.severe("Registration failed: " + e.getMessage());
            throw e;
        }
    }

    public static int authenticateUserAndGetId(String username, String password) throws SQLException {
        String selectQuery = "SELECT id, hash FROM users WHERE username = ?";
        try ( Connection conn = getConnection();  PreparedStatement preparedStatement = conn.prepareStatement(selectQuery)) {

            preparedStatement.setString(1, username);
            try ( ResultSet resultSet = preparedStatement.executeQuery()) {
                if (resultSet.next()) {
                    String hashedPassword = resultSet.getString("hash");
                    if (BCrypt.checkpw(password, hashedPassword)) {
                        // Authentication successful, return user ID
                        return resultSet.getInt("id");
                    } else {
                        AppLogger.warning("User authentication failed for: " + username);
                        return -1; // -1 or any invalid value indicating authentication failure
                    }
                } else {
                    AppLogger.warning("User not found during authentication: " + username);
                    return -1; // -1 or any invalid value indicating user not found
                }
            }
        } catch (SQLException e) {
            AppLogger.severe("Authentication failed: " + e.getMessage());
            throw e;
        }
    }

    public static void insertOnlineUser(String username, String publicKey, String sessionId) throws SQLException {
        // SQL to insert a new online user with the public key and session ID
        String insertQuery = "INSERT INTO onlineusers (username, public_key, session_id) VALUES (?, ?, ?) ON DUPLICATE KEY UPDATE public_key = VALUES(public_key), session_id = VALUES(session_id)";

        try ( Connection conn = getConnection();  PreparedStatement insertStmt = conn.prepareStatement(insertQuery)) {
            // Insert or update the user
            insertStmt.setString(1, username);
            insertStmt.setBytes(2, publicKey.getBytes(StandardCharsets.UTF_8)); // Assuming publicKey is a Base64-encoded string
            insertStmt.setString(3, sessionId);
            insertStmt.execute();

            AppLogger.info("User " + username + " is now online with session ID: " + sessionId);
        } catch (SQLException e) {
            AppLogger.severe("Failed to insert or update online user: " + username + " - " + e.getMessage());
            throw e;
        }
    }

    public static void removeOnlineUser(String username) throws SQLException {
        String deleteQuery = "DELETE FROM onlineusers WHERE username = ?";
        try ( Connection conn = getConnection();  PreparedStatement preparedStatement = conn.prepareStatement(deleteQuery)) {
            preparedStatement.setString(1, username);
            int rowsAffected = preparedStatement.executeUpdate();
            if (rowsAffected > 0) {
                AppLogger.info("Online user removed: " + username);
            } else {
                AppLogger.warning("Failed to remove online user (not found): " + username);
            }
        } catch (SQLException e) {
            AppLogger.severe("Failed to remove online user: " + username + " - " + e.getMessage());
            throw e;
        }
    }

    public static Set<String> getOnlineUsers() throws SQLException {
        Set<String> onlineUsers = new HashSet<>();
        String selectQuery = "SELECT username FROM onlineusers";
        try ( Connection conn = getConnection();  PreparedStatement preparedStatement = conn.prepareStatement(selectQuery);  ResultSet resultSet = preparedStatement.executeQuery()) {
            while (resultSet.next()) {
                onlineUsers.add(resultSet.getString("username"));
            }
            return onlineUsers;
        } catch (SQLException e) {
            AppLogger.severe("Failed to retrieve online users list: " + e.getMessage());
            throw e;
        }
    }

    public List<Message> getChatHistory(int conversationId) {
        List<Message> chatHistory = new ArrayList<>();
        String sql = "SELECT "
                + "    cm.*, "
                + "    sender.username AS sender_username, "
                + "    recipient.username AS recipient_username "
                + "FROM "
                + "    chat_messages AS cm "
                + "INNER JOIN "
                + "    conversations AS c ON cm.conversation_id = c.conversation_id "
                + "INNER JOIN "
                + "    users AS sender ON c.sender_id = sender.id "
                + "INNER JOIN "
                + "    users AS recipient ON c.recipient_id = recipient.id "
                + "WHERE "
                + "    cm.conversation_id = ? "
                + "ORDER BY "
                + "    cm.timestamp";

        Connection conn = null;
        PreparedStatement ps = null;
        ResultSet rs = null;
        try {
            conn = getConnection();
            ps = conn.prepareStatement(sql);
            ps.setInt(1, conversationId);
            rs = ps.executeQuery();

            while (rs.next()) {
                Message message = new Message();
                message.setId(rs.getInt("message_id"));
                message.setSenderId(rs.getInt("sender_id"));
                message.setRecipientId(rs.getInt("recipient_id"));
                message.setContent(rs.getString("content"));
                message.setTimestamp(rs.getTimestamp("timestamp"));
                message.setSenderUsr(rs.getString("sender_username"));
                message.setRecipientUsr(rs.getString("recipient_username"));
                chatHistory.add(message);
            }
        } catch (SQLException e) {
            AppLogger.severe("SQL Exception during chat history retrieval: " + e.getMessage());
            // Depending on how you want to handle the exception, you can either throw it or return a partial result.
            // For example, to throw:
            throw new RuntimeException("Error retrieving chat history", e);
            // Or to handle more gracefully, you might want to return partial data or a specific error message.
        } finally {
            // It's important to close resources in the finally block to avoid leaks.
            try {
                if (rs != null) {
                    rs.close();
                }
                if (ps != null) {
                    ps.close();
                }
                if (conn != null) {
                    conn.close();
                }
            } catch (SQLException e) {
                AppLogger.severe("SQL Exception when closing chat history resources: " + e.getMessage());
            }
        }
        return chatHistory;
    }

    public static void saveChatMessage(int senderId, int recipientId, int conversationId, String content) {
        String insertQuery = "INSERT INTO chat_messages (sender_id, recipient_id, conversation_id, content, timestamp) VALUES (?, ?, ?, ?, NOW())";

        try ( Connection conn = getConnection();  PreparedStatement pstmt = conn.prepareStatement(insertQuery)) {
            pstmt.setInt(1, senderId);
            pstmt.setInt(2, recipientId);
            pstmt.setInt(3, conversationId);
            pstmt.setString(4, content);

            int affectedRows = pstmt.executeUpdate();

            if (affectedRows == 0) {
                throw new SQLException("Creating message failed, no rows affected.");
            }
        } catch (SQLException e) {
            AppLogger.severe("SQL Exception during message save: " + e.getMessage());
        }
    }

    public static int ensureConversation(int user1_id, int user2_id) throws SQLException, GeneralSecurityException {
        // Check if the conversation exists and return its ID if it does.
        Integer conversationId = findExistingConversation(user1_id, user2_id);
        if (conversationId != null) {
            return conversationId;
        }

        // If not, create a new conversation.
        return createNewConversation(user1_id, user2_id);
    }

    public static String getPublicKeyByUserId(int userId) throws SQLException {
        String selectQuery = "SELECT public_key FROM users WHERE id = ?";
        try ( Connection conn = getConnection();  PreparedStatement preparedStatement = conn.prepareStatement(selectQuery)) {
            AppLogger.info("Retrieving public key for user ID: " + userId);

            preparedStatement.setInt(1, userId);
            try ( ResultSet resultSet = preparedStatement.executeQuery()) {
                if (resultSet.next()) {
                    String publicKey = resultSet.getString("public_key");
                    AppLogger.info("Public key retrieved for user ID: " + userId);
                    return publicKey;
                } else {
                    AppLogger.warning("Public key not found for user ID: " + userId);
                    return null;
                }
            }
        } catch (SQLException e) {
            AppLogger.severe("Failed to retrieve public key for user ID: " + userId + " - " + e.getMessage());
            throw e;
        }
    }

    private static Integer findExistingConversation(int sender_id, int recipient_id) throws SQLException {
        String checkQuery = "SELECT conversation_id FROM conversations WHERE (sender_id = ? AND recipient_id = ?) OR (sender_id = ? AND recipient_id = ?)";

        try ( Connection conn = getConnection();  PreparedStatement checkStmt = conn.prepareStatement(checkQuery)) {

            checkStmt.setInt(1, sender_id);
            checkStmt.setInt(2, recipient_id);
            checkStmt.setInt(3, recipient_id);
            checkStmt.setInt(4, sender_id);

            ResultSet resultSet = checkStmt.executeQuery();
            if (resultSet.next()) {
                return resultSet.getInt("conversation_id");
            }
        }

        return null; // Conversation does not exist
    }

    private static byte[] encryptSymmetricKey(byte[] symmetricKeyBytes, String publicKeyStr) throws GeneralSecurityException {
        byte[] publicKeyBytes = Base64.getDecoder().decode(publicKeyStr);
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(publicKeyBytes);
        PublicKey publicKey = KeyFactory.getInstance("RSA").generatePublic(keySpec);

        Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
        OAEPParameterSpec oaepParams = new OAEPParameterSpec(
                "SHA-256", "MGF1", MGF1ParameterSpec.SHA256, PSource.PSpecified.DEFAULT
        );
        cipher.init(Cipher.ENCRYPT_MODE, publicKey, oaepParams);

        return cipher.doFinal(symmetricKeyBytes); // Return the encrypted byte array directly
    }

    private static int createNewConversation(int user1_id, int user2_id) throws SQLException, GeneralSecurityException {
        String insertQuery = "INSERT INTO conversations (sender_id, recipient_id) VALUES (?, ?)";
        int conversationId = -1;

        try ( Connection conn = getConnection();  PreparedStatement insertStmt = conn.prepareStatement(insertQuery, Statement.RETURN_GENERATED_KEYS)) {
            AppLogger.info("Creating new conversation between user " + user1_id + " and user " + user2_id);

            insertStmt.setInt(1, user1_id);
            insertStmt.setInt(2, user2_id);
            int affectedRows = insertStmt.executeUpdate();

            if (affectedRows == 0) {
                AppLogger.warning("No rows affected while creating new conversation.");
                throw new SQLException("Creating conversation failed, no rows affected.");
            }

            try ( ResultSet generatedKeys = insertStmt.getGeneratedKeys()) {
                if (generatedKeys.next()) {
                    conversationId = generatedKeys.getInt(1);
                    AppLogger.info("New conversation created with ID: " + conversationId);
                } else {
                    AppLogger.warning("No ID obtained for new conversation.");
                    throw new SQLException("Creating conversation failed, no ID obtained.");
                }
            }

            // Handle the symmetric key generation and storage
            handleSymmetricKeyForConversation(user1_id, user2_id);

            return conversationId;
        }
    }

    public static byte[] generateSymmetricKeyBytes() throws GeneralSecurityException {
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(256); // for example, use 256 bits for AES
        SecretKey secretKey = keyGen.generateKey();
        return secretKey.getEncoded();
    }

    public static void storeEncryptedSymmetricKey(int userId, int conversationId, byte[] symmetricKeyBytes) throws SQLException, GeneralSecurityException {
        String publicKeyStr = getPublicKeyByUserId(userId);
        if (publicKeyStr == null) {
            AppLogger.warning("Public key not found for user ID: " + userId);
            throw new GeneralSecurityException("Public key not found for user ID: " + userId);
        }

        byte[] encryptedSymmetricKey = encryptSymmetricKey(symmetricKeyBytes, publicKeyStr);

        String insertQuery = "INSERT INTO user_conversation_keys (userId, conversationId, sym_key_usr_encrypted) VALUES (?, ?, ?)";

        try ( Connection conn = getConnection();  PreparedStatement insertStmt = conn.prepareStatement(insertQuery)) {
            insertStmt.setInt(1, userId);
            insertStmt.setInt(2, conversationId);
            insertStmt.setBytes(3, encryptedSymmetricKey);
            int affectedRows = insertStmt.executeUpdate();

            if (affectedRows == 0) {
                AppLogger.warning("Storing encrypted symmetric key failed, no rows affected for user ID: " + userId);
                throw new SQLException("Storing encrypted symmetric key failed, no rows affected.");
            } else {
                AppLogger.info("Encrypted symmetric key stored successfully for user ID: " + userId);
            }
        }
    }

    public static byte[] getEncryptedSymmetricKey(int userId, int conversationId) throws SQLException {
        // SQL query to get the encrypted symmetric key for the user and conversation ID
        String selectQuery = "SELECT sym_key_usr_encrypted FROM user_conversation_keys WHERE userId = ? AND conversationId = ?";
        try ( Connection conn = getConnection();  PreparedStatement preparedStatement = conn.prepareStatement(selectQuery)) {

            preparedStatement.setInt(1, userId);
            preparedStatement.setInt(2, conversationId);
            try ( ResultSet resultSet = preparedStatement.executeQuery()) {
                if (resultSet.next()) {
                    return resultSet.getBytes("sym_key_usr_encrypted");
                } else {
                    // Handle case where there is no key stored for the conversation
                    return null;
                }
            }
        }
    }

    public static String secretKeyToString(SecretKey secretKey) {
        return Base64.getEncoder().encodeToString(secretKey.getEncoded());
    }

    public static SecretKey stringToSecretKey(String keyStr) {
        byte[] decodedKey = Base64.getDecoder().decode(keyStr);
        return new SecretKeySpec(decodedKey, 0, decodedKey.length, "AES");
    }

    public static void handleSymmetricKeyForConversation(int user1_id, int user2_id) throws SQLException, GeneralSecurityException {
        int conversationId = ensureConversation(user1_id, user2_id);
        byte[] symmetricKeyBytes = generateSymmetricKeyBytes();

        // Encrypt and store for both users
        storeEncryptedSymmetricKey(user1_id, conversationId, symmetricKeyBytes);
        storeEncryptedSymmetricKey(user2_id, conversationId, symmetricKeyBytes);

        AppLogger.info("Symmetric key handled for conversation ID: " + conversationId);
    }

}
