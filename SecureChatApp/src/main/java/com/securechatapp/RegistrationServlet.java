package com.securechatapp;

import com.google.gson.Gson;
import com.google.gson.JsonObject;
import org.mindrot.jbcrypt.BCrypt;
import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;
import java.sql.SQLException;
import java.util.stream.Collectors;

@WebServlet("/RegistrationServlet")
public class RegistrationServlet extends HttpServlet {

    protected void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        // Set the response content type to JSON
        response.setContentType("application/json");
        response.setCharacterEncoding("UTF-8");

        // Default values
        int userId;
        String username;
        String password;
        String encPrivateKey;
        String publicKeyBase64;

        // Handle JSON POST request
        String requestBody = request.getReader().lines().collect(Collectors.joining(System.lineSeparator()));
        System.out.println("Req body: " + requestBody);

        // Parse JSON
        Gson gson = new Gson();
        UserRegistrationData data = gson.fromJson(requestBody, UserRegistrationData.class);
        String action = data.getAction(); // Get the action from the parsed JSON

        if ("register".equals(action)) {

            username = data.getUsername();
            password = data.getPassword();
            publicKeyBase64 = data.getPublicKey();
            encPrivateKey = data.getPrivateKey();

            System.out.println("enc key: " + encPrivateKey);

            // Perform server-side validation
            if (!isValidInput(username, password)) {
                JsonObject jsonResponse = new JsonObject();
                jsonResponse.addProperty("status", "error");
                jsonResponse.addProperty("message", "Invalid input. Please check your username and password and try again.");

                response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
                response.getWriter().write(new Gson().toJson(jsonResponse));
                return; // Stop the method if validation fails
            }

            // Generate a salt and hash the password
            String salt = BCrypt.gensalt();
            String hashedPassword = BCrypt.hashpw(password, salt);

            try {

                userId = DatabaseManager.registerUser(username, hashedPassword, salt, publicKeyBase64, encPrivateKey);

                if (userId == -2) {
                    // Username already exists
                    JsonObject jsonResponse = new JsonObject();
                    jsonResponse.addProperty("status", "error");
                    jsonResponse.addProperty("message", "Username already exists.");

                    // Send error status and log
                    response.setStatus(HttpServletResponse.SC_CONFLICT); // 409 Conflict
                    response.getWriter().write(new Gson().toJson(jsonResponse));
                } else if (userId > -1) {
                    // Registration successful
                    JsonObject jsonResponse = new JsonObject();
                    jsonResponse.addProperty("status", "success");
                    jsonResponse.addProperty("userId", userId);
                    jsonResponse.addProperty("message", "Registration successful for Username: " + username);

                    // Set the necessary session attributes
                    HttpSession session = request.getSession();
                    session.setAttribute("username", username);
                    session.setAttribute("userId", userId);
                    session.setAttribute("publicKey", publicKeyBase64);

                    // Convert the JsonObject to a String to send as a response
                    response.getWriter().write(new Gson().toJson(jsonResponse));
                } else {
                    // Other errors (userId = -1)
                    AppLogger.warning("Registration failed for Username: " + username);

                    JsonObject jsonResponse = new JsonObject();
                    jsonResponse.addProperty("status", "error");
                    jsonResponse.addProperty("message", "Registration failed for Username: " + username);

                    // Send error status and log
                    response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
                    response.getWriter().write(gson.toJson(jsonResponse));
                }
            } catch (SQLException e) {
                AppLogger.severe("SQL Exception during registration for Username: " + username + " - " + e.getMessage());

                JsonObject jsonResponse = new JsonObject();
                jsonResponse.addProperty("status", "error");
                jsonResponse.addProperty("message", "Registration failed due to a database error: " + e.getMessage());

                // Send error status and log
                response.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
                response.getWriter().write(gson.toJson(jsonResponse));
            }
        } else {
            // Handle unknown action
            JsonObject jsonResponse = new JsonObject();
            jsonResponse.addProperty("status", "error");
            jsonResponse.addProperty("message", "Unknown action type.");
            response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
            response.getWriter().write(gson.toJson(jsonResponse));
        }
    }

    private boolean isValidInput(String username, String password) {
        // Define the same validation logic as the client-side
        // Username must betwen 8 and 15 characters long and consists of alphanumeric characters and numbers. 
        // Password must be at least 10 characters long, contain at least one uppercase letter, one lowercase letter, one number, and one special character."
        return username.matches("^[a-zA-Z0-9._-]{8,15}$") && password.matches("^(?=.*[a-z])(?=.*[A-Z])(?=.*\\d)(?=.*[@$!%*?&])[A-Za-z\\d@$!%*?&]{10,}$");
    }

    // Inner class to match the JSON structure sent from the client
    private static class UserRegistrationData {

        private String username;
        private String password;
        private String publicKey;
        private String action;
        private String encPrivateKey;

        // Getters and setters are not shown for brevity
        public String getUsername() {
            return username;
        }

        public void setUsername(String username) {
            this.username = username;
        }

        public String getPassword() {
            return password;
        }

        public void setPassword(String password) {
            this.password = password;
        }

        public String getPublicKey() {
            return publicKey;
        }

        public void setPublicKey(String publicKey) {
            this.publicKey = publicKey;
        }

        public String getAction() {
            return action;
        }

        public void setAction(String action) {
            this.action = action;
        }

        public String getPrivateKey() {
            return encPrivateKey;
        }

        public void setPrivateKey(String encPrivateKey) {
            this.encPrivateKey = encPrivateKey;
        }
    }
}
