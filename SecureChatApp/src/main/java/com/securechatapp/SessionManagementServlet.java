package com.securechatapp;

import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;

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

            // Redirect to user dashboard
            response.sendRedirect("chat.jsp");

        } else {
            response.sendRedirect("index.html?error=Invalid+session+request");
        }
    }
}
