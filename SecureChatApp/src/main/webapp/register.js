// This function opens (and creates if necessary) the IndexedDB and then stores the private key
window.openIndexedDB = function openIndexedDB() {
    return new Promise((resolve, reject) => {
        const request = window.indexedDB.open('secure_chat_app', 1);
        request.onupgradeneeded = event => {
            const db = event.target.result;
            db.createObjectStore('keys', {keyPath: 'id'});
        };
        request.onerror = event => reject(`Database error: ${event.target.errorCode}`);
        request.onsuccess = event => resolve(event.target.result);
    });
};

// This function stores the private key in the 'keys' object store
async function storePrivateKey(privateKey) {
    const db = await openIndexedDB();
    return new Promise((resolve, reject) => {
        window.crypto.subtle.exportKey('jwk', privateKey)
                .then(exportedKey => {
                    const transaction = db.transaction('keys', 'readwrite');
                    const objectStore = transaction.objectStore('keys');
                    const request = objectStore.put({id: 'privateKey', key: exportedKey});
                    request.onerror = event => reject(`Error storing the private key: ${event.target.errorCode}`);
                    request.onsuccess = () => resolve('Private key stored successfully');
                })
                .catch(error => reject(`Error exporting the private key: ${error}`));
    });
}

// This function generates an RSA key pair
async function generateAndStoreKeyPair() {
    console.log('Starting key pair generation...');
    try {
        const keyPair = await window.crypto.subtle.generateKey(
                {
                    name: 'RSA-OAEP',
                    modulusLength: 2048,
                    publicExponent: new Uint8Array([1, 0, 1]),
                    hash: {name: 'SHA-256'},
                },
                true, // Set the private key to be extractable
                ['encrypt', 'decrypt']
                );

        console.log('Key pair generated. Storing private key...');
        await storePrivateKey(keyPair.privateKey);
        console.log('Private key stored.');

        // Export the public key and encode it in Base64
        const publicKey = await window.crypto.subtle.exportKey('spki', keyPair.publicKey);
        const publicKeyBase64 = window.btoa(String.fromCharCode(...new Uint8Array(publicKey)));
        document.getElementById('publicKey').value = publicKeyBase64;
        console.log('Public key ready to be sent.');
    } catch (error) {
        console.error('Key pair generation error:', error);
    }
}

async function handleRegistration(event) {
    event.preventDefault(); // Prevent the default form submission
    await generateAndStoreKeyPair();
    sendRegistrationForm();
}

async function sendRegistrationForm() {
    const registrationEndpoint = '/SecureChatApp/RegistrationServlet'; // Ensure the URL is correct
    const username = document.getElementById('username').value;
    const password = document.getElementById('password').value;
    const publicKey = document.getElementById('publicKey').value;

    console.log('Sending registration data to the server...');

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
            console.log('Registration successful', result);
            window.location.href = "chat.jsp"; // Redirect to chat.jsp
        } else {
            // Server responded with an error status
            console.error('Registration failed', result);
            // Redirect to register.jsp with error message
            window.location.href = `register.jsp?error=${encodeURIComponent(result.message)}`;
        }
    } catch (error) {
        console.error('Error during registration:', error);
        // Handle network errors or other exceptions by redirecting to the register page with error message
        window.location.href = `register.jsp?error=${encodeURIComponent(error.message || "An unexpected error occurred.")}`;
    }
}

document.addEventListener('DOMContentLoaded', () => {
    const registrationForm = document.querySelector('#registration-form');
    if (registrationForm) {
        registrationForm.addEventListener('submit', handleRegistration);
    }
});
