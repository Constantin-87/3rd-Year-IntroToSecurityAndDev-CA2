package com.securechatapp;

import com.google.gson.JsonObject;
import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.mindrot.jbcrypt.BCrypt;
import java.io.IOException;
import java.sql.SQLException;
import java.util.stream.Collectors;
import com.google.gson.Gson;
import javax.servlet.http.HttpSession;

@WebServlet("/RegistrationServlet")
public class RegistrationServlet extends HttpServlet {

    protected void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        // Set the response content type to JSON
        response.setContentType("application/json");
        response.setCharacterEncoding("UTF-8");

        // Read request body
        String requestBody = request.getReader().lines().collect(Collectors.joining(System.lineSeparator()));

        // Parse JSON 
        Gson gson = new Gson();
        UserRegistrationData data = gson.fromJson(requestBody, UserRegistrationData.class);

        String username = data.getUsername();
        String password = data.getPassword();
        String publicKeyBase64 = data.getPublicKey();

        // Generate a salt and hash the password
        String salt = BCrypt.gensalt();
        String hashedPassword = BCrypt.hashpw(password, salt);

        try {
            int userId = DatabaseManager.registerUser(username, hashedPassword, salt, publicKeyBase64);

            if (userId > -1) {
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
    }

    // Inner class to match the JSON structure sent from the client
    private static class UserRegistrationData {

        private String username;
        private String password;
        private String publicKey;

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
    }
}
