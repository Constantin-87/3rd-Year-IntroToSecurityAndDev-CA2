// secure.js

// Globally accesable variables
let conversationId, userId, symKey;
let userIdToConversationIdMap = new Map();
let conversationData = new Map();

// On page load open IndexedDB
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
export async function storePrivateKey(privateKey, username) {
    try {
        const db = await openIndexedDB();
        const jwkPrivateKey = await window.crypto.subtle.exportKey('jwk', privateKey);

        const transaction = db.transaction('keys', 'readwrite');
        const objectStore = transaction.objectStore('keys');
        const request = objectStore.put({id: username, key: jwkPrivateKey});

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

export async function generateKeyPair(username, privateKeyPass) {
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
        await storePrivateKey(keyPair.privateKey, username);
        console.log('Created keyPair for username: ', username);

        // Export the public key
        const exportedPublicKey = await window.crypto.subtle.exportKey('spki', keyPair.publicKey);
        const publicKeyBase64 = window.btoa(String.fromCharCode(...new Uint8Array(exportedPublicKey)));
        const publicKeyElement = document.getElementById('publicKey');
        publicKeyElement.value = publicKeyBase64;

        // Export the private key in PKCS#8 format
        const exportedPrivateKey = await window.crypto.subtle.exportKey('pkcs8', keyPair.privateKey);
        const privateKeyBase64 = window.btoa(String.fromCharCode(...new Uint8Array(exportedPrivateKey)));

        // Encrypt the private key with the privateKeyPass
        const encryptedPrivateKey = await encryptPrivateKey(privateKeyBase64, privateKeyPass);

        // Set the encrypted private key to the encPrivateKey element
        const privateKeyElement = document.getElementById('encPrivateKey');
        privateKeyElement.value = encryptedPrivateKey;

    } catch (error) {
        console.error('Error during key pair generation and storage:', error);
    }
}

// Encryption function using the symmetric key and a random IV for each message
export async function encryptMessage(message, symmetricKey) {
    const encoder = new TextEncoder();
    const encodedMessage = encoder.encode(message);
    const iv = window.crypto.getRandomValues(new Uint8Array(12)); // AES-GCM recommended IV size is 12 bytes

    try {
        const encryptedContent = await window.crypto.subtle.encrypt(
                {name: "AES-GCM", iv: iv},
                symmetricKey,
                encodedMessage
                );

        // Return both the encrypted content and the IV for decryption
        return {
            ciphertext: encryptedContent,
            iv: iv
        };
    } catch (error) {
        console.error("Error during encryption:", error);
        throw error;
    }
}

// Utility function to convert an ArrayBuffer to Base64
function arrayBufferToBase64(buffer) {
    let binary = '';
    const bytes = new Uint8Array(buffer);
    for (let i = 0; i < bytes.byteLength; i++) {
        binary += String.fromCharCode(bytes[i]);
    }
    return window.btoa(binary);
}

// Utility function to convert Base64 to an ArrayBuffer
function base64ToArrayBuffer(base64) {
    const binary_string = window.atob(base64);
    const len = binary_string.length;
    const bytes = new Uint8Array(len);
    for (let i = 0; i < len; i++) {
        bytes[i] = binary_string.charCodeAt(i);
    }
    return bytes.buffer;
}

// Function to retrieve and import the private key from IndexedDB
async function getPrivateKey(username) {
    const db = await openIndexedDB();
    return new Promise((resolve, reject) => {
        const transaction = db.transaction('keys', 'readonly');
        const objectStore = transaction.objectStore('keys');
        const request = objectStore.get(username);
        request.onerror = event => reject(`Error retrieving the private key: ${event.target.errorCode}`);
        request.onsuccess = event => {
            if (event.target.result) {
                resolve(event.target.result.key);

            } else {
                reject('No private key found');
            }
        };
    });
}

// Function to import the private key from JWK format to CryptoKey
async function importPrivateKey(jwkKey) {
    const cryptoKey = await window.crypto.subtle.importKey(
            'jwk', // JWK format
            jwkKey,
            {
                name: 'RSA-OAEP',
                hash: {name: 'SHA-256'}
            },
            false, // whether the key is extractable
            ['decrypt'] // only need to decrypt with the private key
            );
    return cryptoKey;
}

// Function to import the symmetric key from an ArrayBuffer to a CryptoKey object
async function importSymmetricKey(keyBuffer) {
    const cryptoKey = await window.crypto.subtle.importKey(
            "raw", // raw format of the key - should be Uint8Array
            keyBuffer,
            {name: "AES-GCM"},
            false, // whether the key is extractable
            ["encrypt", "decrypt"] // can decrypt and encrypot
            );
    return cryptoKey;
}

// Function to decrypt the symmetric key using the user's private key and store it with the conversation ID
export async function decryptAndStoreSymKey(encryptedSymKeyBuffer, conversationId, recipientId, username) {
    try {
        // Retrieve the JWK private key from IndexedDB
        const jwkPrivateKey = await getPrivateKey(username);
        const privateKey = await importPrivateKey(jwkPrivateKey);

        // Decrypt the symmetric key with the private key
        const decryptedSymKeyBuffer = await window.crypto.subtle.decrypt(
                {
                    name: "RSA-OAEP",
                    hash: {name: "SHA-256"}
                },
                privateKey,
                encryptedSymKeyBuffer
                );

        // Import the decrypted symmetric key to a CryptoKey object for use
        const symKey = await importSymmetricKey(decryptedSymKeyBuffer);

        // Store the symmetric key and associate it conversationId and recipientId in the data maps
        if (conversationId && recipientId && symKey) {
            userIdToConversationIdMap.set(recipientId, conversationId);
            conversationData.set(conversationId, {recipientId: recipientId, symKey: symKey});
        } else {
            console.log('decryptAndStoreSymKey: One or more required values are undefined.');
        }
    } catch (error) {
        console.error("Failed to decrypt symmetric key with error:", error);
        throw new Error("Decryption failed: " + error.message);
    }
}


//Function to encrypt messages before sending
export async function encryptForSending(message, conversationId) {
    // Ensure we have a symmetric key for the given conversation ID
    if (!conversationData.has(conversationId)) {
        throw new Error('Symmetric key not found for this conversation.');
    }
    const {symKey} = conversationData.get(conversationId);
    const encryptedData = await encryptMessage(message, symKey);
    const encryptedContent = arrayBufferToBase64(encryptedData.iv) + ':' + arrayBufferToBase64(encryptedData.ciphertext);
    return encryptedContent;
}

export async function decryptForDisplay(encryptedContent, conversationId) {
    // Check if the conversation ID has an associated symmetric key
    if (!conversationData.has(conversationId)) {
        console.error(`No symmetric key found for conversation ID: ${conversationId}`);
        return;
    }
    const {symKey} = conversationData.get(conversationId); // retreive the symmetric key from the map

    // Split the encrypted content into IV and ciphertext
    const parts = encryptedContent.split(':');
    if (parts.length !== 2) {
        console.error("Encrypted content does not have the expected format (IV:ciphertext).", encryptedContent);
        return;
    }
    const [ivBase64, ciphertextBase64] = parts;

    try {
        // Convert Base64 to ArrayBuffer for IV and ciphertext
        const iv = base64ToArrayBuffer(ivBase64);
        const ciphertext = base64ToArrayBuffer(ciphertextBase64);

        // Decrypt the message
        const decryptedContent = await window.crypto.subtle.decrypt(
                {name: "AES-GCM", iv: iv},
                symKey,
                ciphertext
                );
        const decoder = new TextDecoder();
        const plaintext = decoder.decode(decryptedContent);

        return plaintext;
    } catch (error) {
        console.error(`Decryption failed for conversation ID: ${conversationId} with error:`, error);
        return;
    }
}

// Function to check if a private key exists for the given username
export async function checkIfPrivateKeyExists() {
    const db = await openIndexedDB();
    return new Promise((resolve, reject) => {
        const transaction = db.transaction('keys', 'readonly');
        const objectStore = transaction.objectStore('keys');
        const request = objectStore.get(currentUserUsername);
        request.onerror = event => reject(`Error retrieving the private key: ${event.target.errorCode}`);
        request.onsuccess = event => {
            if (event.target.result) {
                resolve(true); // Private key exists
            } else {
                resolve(false); // Private key does not exist
            }
        };
    });
}

// Function to encrypt the private key with the user inputed password (Private Key Password) before sending it to the server 
async function encryptPrivateKey(privateKeyBase64, password) {
    // Encode password as UTF-8
    const pwUtf8 = new TextEncoder().encode(password);

    // Create a random salt
    const salt = window.crypto.getRandomValues(new Uint8Array(16));

    // Derive a key from the password
    const keyMaterial = await window.crypto.subtle.importKey(
            'raw',
            pwUtf8,
            {name: 'PBKDF2'},
            false,
            ['deriveBits', 'deriveKey']
            );

    const key = await window.crypto.subtle.deriveKey(
            {
                name: 'PBKDF2',
                salt: salt,
                iterations: 100000,
                hash: 'SHA-256'
            },
            keyMaterial,
            {name: 'AES-GCM', length: 256},
            false,
            ['encrypt']
            );

    // Convert the private key to an ArrayBuffer for encryption
    const privateKeyBytes = base64ToArrayBuffer(privateKeyBase64);

    // Create a random IV
    const iv = window.crypto.getRandomValues(new Uint8Array(12));

    // Encrypt the private key
    const encryptedPrivateKey = await window.crypto.subtle.encrypt(
            {
                name: 'AES-GCM',
                iv: iv
            },
            key,
            privateKeyBytes
            );

    // Combine the salt, iv, and encrypted private key into a single ArrayBuffer
    const combined = new Uint8Array(salt.length + iv.length + encryptedPrivateKey.byteLength);
    combined.set(salt, 0);
    combined.set(iv, salt.length);
    combined.set(new Uint8Array(encryptedPrivateKey), salt.length + iv.length);

    // Convert the combined ArrayBuffer to a Base64 string
    return arrayBufferToBase64(combined.buffer);
}

// Function to decrypt the private key with the user inputed password (Private Key Password) when receiving it from the server 
export async function decryptPrivateKey(encryptedPrivateKeyBase64, password) {
    // Convert the Base64 string back to an ArrayBuffer
    const encryptedData = base64ToArrayBuffer(encryptedPrivateKeyBase64);

    // Extract the salt and IV from the ArrayBuffer
    const salt = encryptedData.slice(0, 16);
    const iv = encryptedData.slice(16, 28);
    const encryptedPrivateKey = encryptedData.slice(28);

    // Derive the key using the passphrase and salt
    const pwUtf8 = new TextEncoder().encode(password);
    const keyMaterial = await window.crypto.subtle.importKey(
            'raw',
            pwUtf8,
            {name: 'PBKDF2'},
            false,
            ['deriveBits', 'deriveKey']
            );

    const key = await window.crypto.subtle.deriveKey(
            {
                name: 'PBKDF2',
                salt: salt,
                iterations: 100000,
                hash: 'SHA-256'
            },
            keyMaterial,
            {name: 'AES-GCM', length: 256},
            false,
            ['decrypt']
            );

    // Decrypt the private key
    const decryptedPrivateKeyBuffer = await window.crypto.subtle.decrypt(
            {
                name: 'AES-GCM',
                iv: iv
            },
            key,
            encryptedPrivateKey
            );

    // Import the decrypted private key back into a CryptoKey object
    const privateKey = await window.crypto.subtle.importKey(
            'pkcs8',
            decryptedPrivateKeyBuffer,
            {name: 'RSA-OAEP', hash: 'SHA-256'},
            true,
            ['decrypt']
            );

    // Store the decrypted private key using the username as an identifier
    await storePrivateKey(privateKey, currentUserUsername);
}

// Function to verify if the symmetric key exists for a conversation
export function doesSymKeyExistForRecipient(recipientId) {
    const conversationId = userIdToConversationIdMap.get(recipientId);
    if (!conversationId) {
        return false;
    }
    const conversationInfo = conversationData.get(conversationId);    
    return !!(conversationInfo && conversationInfo.symKey);
}

