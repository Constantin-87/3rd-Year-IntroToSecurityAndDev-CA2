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

