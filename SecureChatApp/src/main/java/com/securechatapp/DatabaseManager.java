package com.securechatapp;

import com.zaxxer.hikari.HikariConfig;
import com.zaxxer.hikari.HikariDataSource;
import java.io.IOException;
import java.io.InputStream;
import org.mindrot.jbcrypt.BCrypt;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.X509EncodedKeySpec;
import java.sql.*;
import java.util.*;
import javax.sql.DataSource;

public class DatabaseManager {

    private static DataSource dataSource;

    static {
        Properties dbProps = new Properties();
        String propFileName = "config.properties";
        InputStream is = Thread.currentThread().getContextClassLoader().getResourceAsStream(propFileName);

        if (is == null) {
            AppLogger.severe("Property file '" + propFileName + "' not found in the classpath");
            throw new ExceptionInInitializerError("Property file '" + propFileName + "' not found in the classpath");
        }

        try {
            dbProps.load(is);
            HikariConfig config = new HikariConfig();
            config.setJdbcUrl(dbProps.getProperty("db.url"));
            config.setUsername(dbProps.getProperty("db.user"));
            config.setPassword(dbProps.getProperty("db.password"));
            dataSource = new HikariDataSource(config);
        } catch (IOException e) {
            AppLogger.severe("Failed to load database properties: " + e.getMessage());
            throw new ExceptionInInitializerError(e);
        }
    }

    public static Connection getConnection() throws SQLException {
        return dataSource.getConnection();
    }

    public static int registerUser(String username, String hashedPassword, String salt, String publicKey, String encPrivateKey) throws SQLException {
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
        if (encPrivateKey == null || encPrivateKey.trim().isEmpty()) {
            throw new IllegalArgumentException("Private key cannot be null or empty.");
        }

        // SQL query to check if a user with the given username already exists
        String selectQuery = "SELECT id FROM users WHERE username = ?";
        try ( Connection conn = getConnection();  PreparedStatement checkStmt = conn.prepareStatement(selectQuery)) {
            checkStmt.setString(1, username);

            try ( ResultSet resultSet = checkStmt.executeQuery()) {
                if (resultSet.next()) {
                    AppLogger.warning("Registration failed: Username already exists - " + username);
                    return -2; // Username already exists
                }
            }

            // SQL query to insert a new user with the username, hashed password, salt, and public key
            String insertQuery = "INSERT INTO users (username, hash, salt, public_key, enc_private_key) VALUES (?, ?, ?, ?, ?)";
            try ( PreparedStatement preparedStatement = conn.prepareStatement(insertQuery, Statement.RETURN_GENERATED_KEYS)) {
                preparedStatement.setString(1, username);
                preparedStatement.setString(2, hashedPassword);
                preparedStatement.setString(3, salt);
                preparedStatement.setString(4, publicKey);
                preparedStatement.setString(5, encPrivateKey);
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

    // Ensures that a conversation is in place and returns its ID
    public static int ensureConversation(int user1_id, int user2_id) {
        try {
            Integer conversationId = findExistingConversation(user1_id, user2_id);
            if (conversationId != null) {
                return conversationId;
            }
            return createNewConversation(user1_id, user2_id);
        } catch (SQLException | GeneralSecurityException e) {
            AppLogger.severe("Exception in ensureConversation: " + e.getMessage());
            throw new RuntimeException("Error ensuring conversation", e);
        }
    }

    public static String getPublicKeyByUserId(int userId) throws SQLException {
        String selectQuery = "SELECT public_key FROM users WHERE id = ?";
        try ( Connection conn = getConnection();  PreparedStatement preparedStatement = conn.prepareStatement(selectQuery)) {

            preparedStatement.setInt(1, userId);
            try ( ResultSet resultSet = preparedStatement.executeQuery()) {
                if (resultSet.next()) {
                    String publicKey = resultSet.getString("public_key");
                    return publicKey;
                } else {
                    AppLogger.warning("Public key not found for user ID: " + userId);
                    return null;
                }
            }
        } catch (SQLException e) {
            AppLogger.severe("Failed to retrieve public key for user ID: " + userId + " - " + e.getMessage());
            throw new RuntimeException("Error retrieving public key", e);
        }
    }

    public static String getPrivateKeyByUserId(int userId) throws SQLException {
        String selectQuery = "SELECT enc_private_key FROM users WHERE id = ?";
        try ( Connection conn = getConnection();  PreparedStatement preparedStatement = conn.prepareStatement(selectQuery)) {

            preparedStatement.setInt(1, userId);
            try ( ResultSet resultSet = preparedStatement.executeQuery()) {
                if (resultSet.next()) {
                    String privateKey = resultSet.getString("enc_private_key");
                    return privateKey;
                } else {
                    AppLogger.warning("Private key not found for user ID: " + userId);
                    return null;
                }
            }
        } catch (SQLException e) {
            AppLogger.severe("Failed to retrieve public key for user ID: " + userId + " - " + e.getMessage());
            throw new RuntimeException("Error retrieving public key", e);
        }
    }

    private static Integer findExistingConversation(int sender_id, int recipient_id) throws SQLException {
        String checkQuery = "SELECT conversation_id FROM conversations WHERE (sender_id = ? AND recipient_id = ?) OR (sender_id = ? AND recipient_id = ?)";

        try ( Connection conn = getConnection();  PreparedStatement checkStmt = conn.prepareStatement(checkQuery)) {

            checkStmt.setInt(1, sender_id);
            checkStmt.setInt(2, recipient_id);
            checkStmt.setInt(3, recipient_id);
            checkStmt.setInt(4, sender_id);

            try ( ResultSet resultSet = checkStmt.executeQuery()) {
                if (resultSet.next()) {
                    return resultSet.getInt("conversation_id");
                }
            }
        } catch (SQLException e) {
            AppLogger.severe("SQL Exception in findExistingConversation: " + e.getMessage());
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
        int conversationId;

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
            handleSymmetricKeyForConversation(user1_id, user2_id, conversationId);

            return conversationId;
        }
    }

    public static byte[] generateSymmetricKeyBytes() throws GeneralSecurityException {
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(256); // for example, use 256 bits for AES
        SecretKey secretKey = keyGen.generateKey();
        return secretKey.getEncoded();
    }

    public static void storeEncryptedSymmetricKey(int conversationId, byte[] symmetricKeyBytes, int user_id) throws SQLException, GeneralSecurityException {

        String userPublicKeyStr = getPublicKeyByUserId(user_id);
        byte[] encryptedSymmetricKey = encryptSymmetricKey(symmetricKeyBytes, userPublicKeyStr);

        String insertQuery = "INSERT INTO user_conversation_keys (conversationId, sym_key_usr_encrypted, user_id) VALUES (?, ?, ?)";

        try ( Connection conn = getConnection();  PreparedStatement insertStmt = conn.prepareStatement(insertQuery)) {
            insertStmt.setInt(1, conversationId);
            insertStmt.setBytes(2, encryptedSymmetricKey);
            insertStmt.setInt(3, user_id);
            int affectedRows = insertStmt.executeUpdate();

            if (affectedRows == 0) {
                throw new SQLException("Storing encrypted symmetric key failed, no rows affected.");
            } else {
                AppLogger.info("Encrypted symmetric key stored successfully for user conversation id: " + conversationId);
            }
        }
    }

    public static byte[] getEncryptedSymmetricKey(int userId, int conversationId) throws SQLException, GeneralSecurityException {
        // SQL query to get the encrypted symmetric key for the user and conversation ID
        String selectQuery = "SELECT sym_key_usr_encrypted FROM user_conversation_keys WHERE user_id = ? AND conversationId = ?";

        try ( Connection conn = getConnection();  PreparedStatement preparedStatement = conn.prepareStatement(selectQuery)) {

            preparedStatement.setInt(1, userId);
            preparedStatement.setInt(2, conversationId);

            try ( ResultSet resultSet = preparedStatement.executeQuery()) {
                if (resultSet.next()) {
                    // Return the encrypted symmetric key as it is
                    return resultSet.getBytes("sym_key_usr_encrypted");
                } else {
                    // No symmetric key found for the provided user_id and conversationId
                    AppLogger.info("No encrypted symmetric key found for user_id: " + userId + " and conversationId: " + conversationId);
                    return null;
                }
            }
        }
    }

    /*
    public static String secretKeyToString(SecretKey secretKey) {
        return Base64.getEncoder().encodeToString(secretKey.getEncoded());
    }

    public static SecretKey stringToSecretKey(String keyStr) {
        byte[] decodedKey = Base64.getDecoder().decode(keyStr);
        return new SecretKeySpec(decodedKey, 0, decodedKey.length, "AES");
    }
     */
    public static void handleSymmetricKeyForConversation(int user1_id, int user2_id, int conversationId) throws SQLException, GeneralSecurityException {

        byte[] symmetricKeyBytes = generateSymmetricKeyBytes();

        // Encrypt and store for both users
        storeEncryptedSymmetricKey(conversationId, symmetricKeyBytes, user1_id);
        storeEncryptedSymmetricKey(conversationId, symmetricKeyBytes, user2_id);

        AppLogger.info("Symmetric key handled for conversation ID: " + conversationId);
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

        try ( Connection conn = getConnection();  PreparedStatement ps = conn.prepareStatement(sql)) {

            ps.setInt(1, conversationId);

            try ( ResultSet rs = ps.executeQuery()) {
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
            }
        } catch (SQLException e) {
            AppLogger.severe("SQL Exception during chat history retrieval: " + e.getMessage());
            // Here you can either throw a RuntimeException to indicate an unrecoverable error
            // or you can choose to return partial data or an error message.
            throw new RuntimeException("Error retrieving chat history", e);
        }
        return chatHistory;
    }

}
