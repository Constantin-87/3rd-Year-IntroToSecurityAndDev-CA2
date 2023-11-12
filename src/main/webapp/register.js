window.openIndexedDB = function openIndexedDB() {
    return new Promise((resolve, reject) => {
        console.log('Opening IndexedDB...');
        const request = window.indexedDB.open('secure_chat_app', 1);
        request.onupgradeneeded = event => {
            const db = event.target.result;
            db.createObjectStore('keys', {keyPath: 'id'});
            console.log('IndexedDB onupgradeneeded: Object store created.');
        };
        request.onerror = event => {
            console.error(`IndexedDB error: ${event.target.errorCode}`);
            reject(`Database error: ${event.target.errorCode}`);
        };
        request.onsuccess = event => {
            console.log('IndexedDB opened successfully.');
            resolve(event.target.result);
        };
    });
};

// This function stores the private key in the 'keys' object store
async function storePrivateKey(privateKey) {
    try {
        const db = await openIndexedDB();
        const jwkPrivateKey = await window.crypto.subtle.exportKey('jwk', privateKey);
        console.log('Exported Private Key (JWK):', JSON.stringify(jwkPrivateKey, null, 2));

        const transaction = db.transaction('keys', 'readwrite');
        const objectStore = transaction.objectStore('keys');
        const request = objectStore.put({id: 'privateKey', key: jwkPrivateKey});

        return new Promise((resolve, reject) => {
            request.onerror = event => {
                console.error(`Error storing the private key: ${event.target.errorCode}`);
                reject(`Error storing the private key: ${event.target.errorCode}`);
            };
            request.onsuccess = () => {
                console.log('Private key stored successfully in IndexedDB.');
                resolve('Private key stored successfully');
            };
        });
    } catch (error) {
        console.error(`Error during private key storage: ${error}`);
        throw error;
    }
}

async function generateAndStoreKeyPair() {
    try {
        const keyPair = await window.crypto.subtle.generateKey(
                {
                    name: 'RSA-OAEP',
                    modulusLength: 2048,
                    publicExponent: new Uint8Array([1, 0, 1]),
                    hash: {name: 'SHA-256'}
                },
                true,
                ['encrypt', 'decrypt']
                );

        // Store the private key in IndexedDB
        await storePrivateKey(keyPair.privateKey);

        // Export the private key and print it to the console
        const exportedPrivateKey = await window.crypto.subtle.exportKey("pkcs8", keyPair.privateKey);
        const privateKeyBase64 = window.btoa(String.fromCharCode(...new Uint8Array(exportedPrivateKey)));
        const pemExportedPrivateKey = `-----BEGIN PRIVATE KEY-----\n${privateKeyBase64}\n-----END PRIVATE KEY-----`;
        console.log('Private key generated: ', pemExportedPrivateKey);

        // Export the public key and print it to the console
        const exportedPublicKey = await window.crypto.subtle.exportKey('spki', keyPair.publicKey);
        const publicKeyBase64 = window.btoa(String.fromCharCode(...new Uint8Array(exportedPublicKey)));
        const pemExportedPublicKey = `-----BEGIN PUBLIC KEY-----\n${publicKeyBase64}\n-----END PUBLIC KEY-----`;
        console.log('Public key generated: ', pemExportedPublicKey);

        // Store the public key in a form field
        document.getElementById('publicKey').value = publicKeyBase64;
        console.log('Public key Base64 ready to be sent:', publicKeyBase64);
    } catch (error) {
        console.error('Error during key pair generation and storage:', error);
    }
}


async function handleRegistration(event) {
    event.preventDefault(); // Prevent the default form submission
    await generateAndStoreKeyPair();
    await sendRegistrationForm();
}

async function sendRegistrationForm() {
    const registrationEndpoint = '/SecureChatApp/RegistrationServlet'; // Ensure the URL is correct
    const username = document.getElementById('username').value;
    const password = document.getElementById('password').value;
    const publicKey = document.getElementById('publicKey').value;

    console.log('Sending registration data to the server...');
    // Validate the input before sending
    const validationResult = validateInput(username, password);
    if (!validationResult.isValid) {
        displayErrorMessage(validationResult.message, false); // Display error message
        return; // Stop the function if validation fails
    }

    try {
        const response = await fetch(registrationEndpoint, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                username: username,
                password: password,
                publicKey: publicKey
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
function validateInput(username, password) {
    // Define regex patterns for validation same as on the server-side
    const usernamePattern = /^[a-zA-Z0-9._-]{8,15}$/;
    const passwordPattern = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{10,}$/;
    let result = {isValid: true, message: ""};

    if (!usernamePattern.test(username) && !passwordPattern.test(password)) {
        result.isValid = false;
        result.message = "Invalid username and password.";
    } else if (!usernamePattern.test(username)) {
        result.isValid = false;
        result.message = "Username must betwen 8 and 15 characters long and consists of alphanumeric characters or numbers.";
    } else if (!passwordPattern.test(password)) {
        result.isValid = false;
        result.message = "Password must be at least 10 characters long, " +
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
    console.log('In addEventListener');
    if (registrationForm) {
        registrationForm.addEventListener('submit', handleRegistration);
    }
});

