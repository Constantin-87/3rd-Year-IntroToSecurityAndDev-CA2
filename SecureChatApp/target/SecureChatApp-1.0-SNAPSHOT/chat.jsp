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
            Integer userIdInt = null;
            if (session != null) {
                username = (String) session.getAttribute("username");
                userIdInt = (Integer) session.getAttribute("userId");
            }
            if (username == null || username.trim().isEmpty()) {
                response.sendRedirect("index.html");
                return;
            }
        %>
        <header>
            <div id="title-container">
                <h1>Secure Chat App</h1> <!-- Title of the page -->
            </div>
            <div id="user-logout-container">
                <!-- Current user display -->
                <div id="current-user">Logged in as: <span><%= username%></span></div>
                <!-- Logout button -->
                <div id="logout-area">
                    <button id="logout-button" onclick="location.href = 'logoutServlet';">Logout</button>
                </div>
            </div>
            <div id="chat-with">                 
                <!-- Chat partner name will be dynamically inserted here -->
                <span >Select a user to chat with</span> <!-- Chat with display -->
            </div>
        </header>

        <div id="chat-container">
            <!-- Sidebar for online users -->
            <aside id="users-sidebar">
                <!-- Online user buttons will be dynamically inserted here -->
            </aside>
            <!-- Chat area -->
            <section id="chat-area">
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
            var currentUserId = <%= userIdInt != null ? userIdInt : "null"%>;
        </script>
        <script type="module" src="register.js"></script>
        <script type="module" src="secure.js"></script>
        <script type="module" src="chat.js"></script>
    </body>
</html>
