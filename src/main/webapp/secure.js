// secure.js

var conversationId, userId, symKey;
let conversationData = new Map();
conversationData.set(conversationId, {
    userId: userId,
    symKey: symKey
});

export { conversationData };

// Encryption function using the symmetric key and a random IV for each message
export async function encryptMessage(message, symmetricKey) {
    console.log("Starting message encryption...");
    const encoder = new TextEncoder();
    const encodedMessage = encoder.encode(message);
    const iv = window.crypto.getRandomValues(new Uint8Array(12)); // AES-GCM recommended IV size is 12 bytes
    console.log("IV generated for encryption:", iv);

    try {
        const encryptedContent = await window.crypto.subtle.encrypt(
                {name: "AES-GCM", iv: iv},
                symmetricKey,
                encodedMessage
                );
        console.log("Encryption successful, encrypted content:", encryptedContent);

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

// Decryption function using the symmetric key and the IV that was used during encryption
export async function decryptMessage(encryptedContent, symmetricKey) {
    console.log("Decrypting message...");
    console.log("symmetricKey: ", symmetricKey);
    try {
        const decryptedContent = await window.crypto.subtle.decrypt(
                {name: "AES-GCM", iv: encryptedContent.iv},
                symmetricKey,
                encryptedContent.ciphertext
                );
        const decoder = new TextDecoder();
        const decodedMessage = decoder.decode(decryptedContent);
        console.log("Message decryption successful.");
        return decodedMessage;
    } catch (error) {
        console.error("Decryption failed:", error);
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
async function getPrivateKey() {
    const db = await openIndexedDB(); // This function should be available from register.js
    return new Promise((resolve, reject) => {
        const transaction = db.transaction('keys', 'readonly');
        const objectStore = transaction.objectStore('keys');
        const request = objectStore.get('privateKey');
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
            true, // whether the key is extractable
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
            false, // whether the key is extractable (i.e. can be used in exportKey)
            ["encrypt", "decrypt"] // can "encrypt", "decrypt", "wrapKey", or "unwrapKey"
            );

    // Log the imported key for debugging
    console.log("Imported symmetric key:", cryptoKey);

    return cryptoKey;
}

// Function to decrypt the symmetric key using your private key and store it with the conversation ID
export async function decryptAndStoreSymKey(encryptedSymKeyBuffer, conversationId, userId) {
    try {
        // encryptedSymKeyBuffer is already an ArrayBuffer, so we don't need to call .arrayBuffer() on it

        // Retrieve the JWK private key from IndexedDB
        const jwkPrivateKey = await getPrivateKey();
        const privateKey = await importPrivateKey(jwkPrivateKey);

        // Decrypt the symmetric key with the private key
        const decryptedSymKeyBuffer = await window.crypto.subtle.decrypt(
                {
                    name: "RSA-OAEP",
                    hash: {name: "SHA-256"}
                },
                privateKey,
                encryptedSymKeyBuffer  // Use the ArrayBuffer directly
                );

        console.log(`Symmetric key stored for conversation ID: ${conversationId} with userId: ${userId}`);

        // Import the decrypted symmetric key to a CryptoKey object for use
        const symKey = await importSymmetricKey(decryptedSymKeyBuffer);

        // Store the symmetric key in the map with the conversation ID as the key
        conversationData.set(conversationId, {userId: userId, symKey: symKey});
    } catch (error) {
        console.error("Failed to decrypt symmetric key with error:", error);
        throw new Error("Decryption failed: " + error.message);
    }
}

export async function encryptForSending(message, conversationId) {
    // Ensure we have a symmetric key for the given conversation ID
    if (!conversationData.has(conversationId)) {
        throw new Error('Symmetric key not found for this conversation.');
    }

    console.log(`Encrypting message for conversation ID: ${conversationId}`);
    const {symKey} = conversationData.get(conversationId);
    const encryptedData = await encryptMessage(message, symKey);
    const encryptedContent = arrayBufferToBase64(encryptedData.iv) + ':' + arrayBufferToBase64(encryptedData.ciphertext);
    console.log(`Encrypted content: ${encryptedContent}`);
    return encryptedContent;
}

export async function decryptForDisplay(encryptedContent, conversationId) {
    console.log("Received encrypted content for decryption:", encryptedContent);
    console.log("Using conversationId for decryption:", conversationId);

    // Check if the conversation ID has an associated symmetric key
    if (!conversationData.has(conversationId)) {
        console.error(`No symmetric key found for conversation ID: ${conversationId}`);
        return;
    }

    const {symKey} = conversationData.get(conversationId);
    console.log(`Retrieved symmetric key for conversation ID ${conversationId}:`, symKey);

    // Split the encrypted content into IV and ciphertext
    const parts = encryptedContent.split(':');
    if (parts.length !== 2) {
        console.error("Encrypted content does not have the expected format (IV:ciphertext).", encryptedContent);
        return;
    }

    const [ivBase64, ciphertextBase64] = parts;
    console.log("IV (Base64):", ivBase64);
    console.log("Ciphertext (Base64):", ciphertextBase64);

    try {
        // Convert Base64 to ArrayBuffer for IV and ciphertext
        const iv = base64ToArrayBuffer(ivBase64);
        const ciphertext = base64ToArrayBuffer(ciphertextBase64);
        console.log("IV (ArrayBuffer):", iv);
        console.log("Ciphertext (ArrayBuffer):", ciphertext);

        // Decrypt the message
        const decryptedContent = await window.crypto.subtle.decrypt(
                {name: "AES-GCM", iv: iv},
                symKey,
                ciphertext
                );
        const decoder = new TextDecoder();
        const plaintext = decoder.decode(decryptedContent);
        console.log("Decrypted message:", plaintext);

        return plaintext;
    } catch (error) {
        console.error(`Decryption failed for conversation ID: ${conversationId} with error:`, error);
        return;
    }
}