import {generateKeyPair} from './secure.js';

async function handleRegistration(event) {
    event.preventDefault(); // Prevent the default form submission
    // Validate the input before sending
    const username = document.getElementById('username').value;
    const password = document.getElementById('password').value;
    const privateKeyPass = document.getElementById('privateKeyPassphrase').value;
    
    const validationResult = validateInput(username, password, privateKeyPass);
    if (!validationResult.isValid) {
        displayErrorMessage(validationResult.message, false); // Display error message
        return; // Stop the function if validation fails
    }
    
    await generateKeyPair(username, privateKeyPass);
    await sendRegistrationForm(username, password);
}

async function sendRegistrationForm(username, password) {

    const registrationEndpoint = '/SecureChatApp/RegistrationServlet'; // Ensure the URL is correct

    const publicKey = document.getElementById('publicKey').value;
    const encPrivateKey = document.getElementById('encPrivateKey').value;
    console.log('Sending registration data to the server, username: ${username}, password: ${password}, publicKey: ${publicKey}, encPrivateKey: ${encPrivateKey}');
    try {
        const response = await fetch(registrationEndpoint, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                action: "register",
                username: username,
                password: password,
                publicKey: publicKey,
                encPrivateKey: encPrivateKey
            })
        });

        const result = await response.json(); // Assuming the server always returns JSON.

        if (response.ok && result.status === "success") {
            // Registration successful
            displayErrorMessage(`Registration successful. Welcome, ${username}! You will be redirected to the chat.`, true); // Display success message
            // Redirect to chat.jsp after a slight delay
            setTimeout(() => {
                window.location.href = "chat.jsp";
            }, 3000); // 3 seconds delay
        } else {
            // Server responded with an error status
            displayErrorMessage(`Registration failed: ${result.message}`, false); // Display error message
        }
    } catch (error) {
        console.error('Error during registration:', error);
        displayErrorMessage(error.message || "An unexpected error occurred during registration.", false); // Display error message
    }
}

// Function to validate the username and password format
function validateInput(username, password, privateKeyPass) {
    // Define regex patterns for validation same as on the server-side
    const usernamePattern = /^[a-zA-Z0-9._-]{8,15}$/;
    const passwordPattern = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{10,}$/;
    const privateKeyPassPattern = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{10,}$/;
    let result = {isValid: true, message: ""};

    if (!usernamePattern.test(username)) {
        result.isValid = false;
        result.message = "Username must betwen 8 and 15 characters long and consists of alphanumeric characters or numbers.";
    } else if (!passwordPattern.test(password)) {
        result.isValid = false;
        result.message = "Password must be at least 10 characters long, " +
                "contain at least one uppercase letter, one lowercase letter, " +
                "one number, and one special character.";
    } else if (!privateKeyPassPattern.test(privateKeyPass)) {
        result.isValid = false;
        result.message = "Private key password must be at least 10 characters long, " +
                "contain at least one uppercase letter, one lowercase letter, " +
                "one number, and one special character.";
    }
    return result;
}

// Helper function to display error messages
function displayErrorMessage(message, isSuccess) {
    // Select the error message element from the DOM
    const errorMessageElement = document.getElementById('error-message');

    // Display the message
    errorMessageElement.textContent = message;
    errorMessageElement.style.display = 'block'; // Make sure to display the element if it was hidden

    // If it's a success message, change the style accordingly
    if (isSuccess) {
        errorMessageElement.style.color = 'green';
    } else {
        errorMessageElement.style.color = 'red';
    }
}

document.addEventListener('DOMContentLoaded', () => {
    const registrationForm = document.querySelector('#registrationForm');
    if (registrationForm) {
        registrationForm.addEventListener('submit', handleRegistration);
    }
});

