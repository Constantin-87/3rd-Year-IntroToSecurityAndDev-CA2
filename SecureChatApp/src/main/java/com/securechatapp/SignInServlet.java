package com.securechatapp;

import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;
import java.net.URLEncoder;
import java.sql.SQLException;

@WebServlet("/SignInServlet")
public class SignInServlet extends HttpServlet {

    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String username = request.getParameter("username");
        String password = request.getParameter("password");

        // First, validate the input before attempting to authenticate with the database
        if (!isValidInput(username, password)) {
            // Invalid input; redirect back to the sign-in page with an error message
            String errorMessage = URLEncoder.encode("Invalid input. Please check your username and password and try again.", "UTF-8");
            response.sendRedirect("index.html?error=" + errorMessage);
            return;
        }

        try {
            // Input is valid; proceed to authenticate the user
            int userId = DatabaseManager.authenticateUserAndGetId(username, password);

            if (userId > -1) {
                // User is valid; redirect to a servlet that handles the session logic and pass both the username and user ID as query parameters
                String publicKey = DatabaseManager.getPublicKeyByUserId(userId);

                // Set the user information as session attributes
                HttpSession session = request.getSession();
                session.setAttribute("username", username);
                session.setAttribute("userId", userId);
                session.setAttribute("publicKey", publicKey);

                response.sendRedirect("sessionManagementServlet");
            } else {
                // Sign-in failed; redirect back to the sign-in page with an error message
                response.sendRedirect("index.html?error=Invalid+credentials");
            }
        } catch (SQLException e) {
            // Log the SQL exception
            AppLogger.severe("SQL Exception during sign-in for Username: " + username + " - " + e.getMessage());

            // Handle the SQL exception here by sending back the specific error message
            String errorMessage = URLEncoder.encode("Sign-in failed due to a system error. Please try again later.", "UTF-8");
            response.sendRedirect("index.html?error=" + errorMessage);
        }
    }

    private boolean isValidInput(String username, String password) {
        // Define the same validation logic as the client-side
        // Username must betwen 8 and 15 characters long and consists of alphanumeric characters and numbers. 
        // Password must be at least 10 characters long, contain at least one uppercase letter, one lowercase letter, one number, and one special character."
        return username.matches("^[a-zA-Z0-9._-]{8,15}$") && password.matches("^(?=.*[a-z])(?=.*[A-Z])(?=.*\\d)(?=.*[@$!%*?&])[A-Za-z\\d@$!%*?&]{10,}$");
    }
}
