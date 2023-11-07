<%@ page contentType="text/html;charset=UTF-8" language="java" %>
<%@ page import="javax.servlet.http.HttpSession" %>
<!DOCTYPE html>
<html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Chat Application</title>
        <link rel="stylesheet" href="style.css">
    </head>
    <body>

        <%
            String username = null;
            Integer userIdInt = null; // Changed from String to Integer
            if (session != null) {
                username = (String) session.getAttribute("username");
                userIdInt = (Integer) session.getAttribute("userId"); // No casting to String here
            }
            if (username == null || username.trim().isEmpty()) {
                // Redirect to login if the username isn't present in the session
                response.sendRedirect("index.html");
                return;
            }
        %>

        <div style="display: flex; justify-content: space-between; align-items: center; padding: 10px; background: #f0f0f0;">
            <!-- Current user display -->
            <div id="current-user" style="font-weight: bold;">Logged in as: <span id="username"><%= username%></span></div>

            <!-- Logout button -->
            <div id="logout-area">
                <button id="logout-button" onclick="location.href = 'logoutServlet';">Logout</button>
            </div>
        </div>

        <!-- Chat header -->
        <div id="chat-header" style="padding: 10px; background: #e6e6e6; border-bottom: 1px solid #ccc;">
            <!-- Chat partner name will be dynamically inserted here -->
            <span id="chat-with">Select a user to chat with</span>
        </div>

        <div style="display: flex; height: 700px;">
            <!-- Sidebar for online users -->
            <aside id="users-sidebar" style="width: 150px; background: #e6e6e6; overflow-y: auto; padding: 10px;">
                <!-- Online user buttons will be dynamically inserted here -->
            </aside>

            <!-- Chat area -->
            <section id="chat-area" style="flex-grow: 1; background: #f9f9f9; overflow-y: auto; width: 700px; padding: 10px;">
                <!-- Chat content for the selected user will be dynamically inserted here -->
            </section>
        </div>

        <div id="input-container">
            <!-- Message input -->
            <textarea id="message-input" placeholder="Type a message..."></textarea>

            <!-- Send button -->
            <button id="send-button">Send</button>
        </div>

        <script type="text/javascript">
            var currentUserUsername = '<%= username%>';
            var currentUserId = <%= userIdInt != null ? userIdInt : "null"%>; // Keep as Integer for JavaScript
        </script>
        <script src="register.js"></script>
        <script src="secure.js"></script>
        <script src="chat.js"></script>

    </body>
</html>
