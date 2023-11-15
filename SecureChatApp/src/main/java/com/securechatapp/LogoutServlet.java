package com.securechatapp;

import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;
import java.util.concurrent.ConcurrentHashMap;

@WebServlet("/logoutServlet")
public class LogoutServlet extends HttpServlet {

    private static final ConcurrentHashMap<String, Boolean> logoutSessions = new ConcurrentHashMap<>();

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        // Sessions are usually managed in doGet for logout functionality
        handleLogout(request);
        response.sendRedirect("index.html");
    }

    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        handleLogout(request);
        response.sendRedirect("index.html");
    }

    private void handleLogout(HttpServletRequest request) {
        HttpSession session = request.getSession(false);
        if (session != null) {
            String sessionId = session.getId();

            // Atomically check if logout is already in progress for this session
            if (logoutSessions.putIfAbsent(sessionId, Boolean.TRUE) != null) {
                // If the previous value was not null, it means logout is already in progress
                return;
            }

            session.invalidate();
            logoutSessions.remove(sessionId);
        }
    }
}
