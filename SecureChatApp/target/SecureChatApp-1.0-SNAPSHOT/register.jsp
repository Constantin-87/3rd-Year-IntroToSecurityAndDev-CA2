<%@ page language="java" contentType="text/html; charset=UTF-8" pageEncoding="UTF-8" %>
<!DOCTYPE html>
<html>
    <head>
        <title>User Registration</title>
        <link rel="stylesheet" href="style.css">
        <script type="module" src="register.js"></script>
    </head>
    <body>
        <header>
            <div id="title-container">
                <h1>User Registration</h1> <!-- Title of the page -->
            </div>
        </header>
        <main id="main-container">
            <div id="error-message"></div>
            <form id="registrationForm" action="RegistrationServlet" method="post" onsubmit="handleRegistration(event)" class="form-container">
                <div class="input-group">
                    Username: <input type="text" id="username" name="username" required>
                </div>
                <div class="input-group">
                    Password: <input type="password" id="password" name="password" required>
                </div>
                <div class="input-group">
                    Private Key Password: <input type="password" id="privateKeyPassphrase" name="privateKeyPassphrase" required>
                </div>
                <input type="hidden" id="publicKey" name="publicKey">
                <input type="hidden" id="encPrivateKey" name="encPrivateKey">
                <button type="submit" id="submit-button" class="action-button">Register</button>

                <button onclick="location.href = 'index.html'" id="back-button" class="action-button">Back</button>
            </form>

        </main>
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
