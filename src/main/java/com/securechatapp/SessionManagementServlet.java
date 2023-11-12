package com.securechatapp;

import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;
import java.sql.SQLException;

@WebServlet("/sessionManagementServlet")
public class SessionManagementServlet extends HttpServlet {

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        // Ensure that the connection is secure
        if (!request.isSecure()) {
            response.sendRedirect("index.html?error=Insecure+connection");
            return;
        }

        HttpSession session = request.getSession(false); // Don't create a new session if one doesn't exist

        if (session != null && session.getAttribute("username") != null && session.getAttribute("publicKey") != null) {
            String username = (String) session.getAttribute("username");
            String publicKeyString = (String) session.getAttribute("publicKey");

            try {
                // Regenerate session ID to prevent fixation
                request.changeSessionId();

                // Insert the user into the online users table with their public key and session ID
                DatabaseManager.insertOnlineUser(username, publicKeyString, session.getId());

                // Redirect to user dashboard
                response.sendRedirect("chat.jsp");
            } catch (SQLException e) {
                AppLogger.severe("SQL error during session initialization for user " + username + ": " + e.getMessage());
                response.sendRedirect("index.html?error=Unable+to+create+session");
            }
        } else {
            response.sendRedirect("index.html?error=Invalid+session+request");
        }
    }
}
