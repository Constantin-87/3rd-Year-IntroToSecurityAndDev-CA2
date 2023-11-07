<%@ page language="java" contentType="text/html; charset=UTF-8" pageEncoding="UTF-8"%>
<!DOCTYPE html>
<html>
    <head>
        <title>User Registration</title>
        <!-- Include the register.js file -->
        <script src="register.js"></script>
    </head>
    <body>
        <h1>User Registration</h1>
        <div id="error-message" style="color: red;"></div>
        <form id="registrationForm" action="RegistrationServlet" method="post" onsubmit="handleRegistration(event)">
            Username: <input type="text" id="username" name="username" required pattern="^[a-zA-Z0-9]{5,}$" title="Username should be at least 5 characters long and only contain letters and numbers."><br><br>
            Password: <input type="password" id="password" name="password" required pattern=".{8,}" title="Password should be at least 8 characters."><br><br>
            <!-- Hidden field to store the base64 encoded public key -->
            <input type="hidden" id="publicKey" name="publicKey">
            <input type="submit" value="Register">
        </form>

        <button onclick="location.href = 'index.jsp'">Back</button>

        <script>
            // This script checks for a query string and displays an error message if present
            window.onload = function () {
                var urlParams = new URLSearchParams(window.location.search);
                var error = urlParams.get('error');
                if (error) {
                    document.getElementById('error-message').textContent = error.replace(/\+/g, ' ');
                }
            };
        </script>
    </body>
</html>
