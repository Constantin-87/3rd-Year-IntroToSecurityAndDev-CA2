// secure.js

// Encryption function using the symmetric key and a random IV for each message
async function encryptMessage(message, symmetricKey) {
    console.log("Encrypting message...");
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
        console.log("Message encryption successful.");
        // Return both the encrypted content and the IV for decryption
        return {
            ciphertext: encryptedContent,
            iv: iv
        };
    } catch (error) {
        console.error("Encryption failed:", error);
        throw error;
    }
}

// Decryption function using the symmetric key and the IV that was used during encryption
async function decryptMessage(encryptedContent, symmetricKey) {
    console.log("Decrypting message...");
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

// Function to decrypt the symmetric key using your private key
async function decryptSymmetricKey(encryptedSymKey) {
    console.log("In: decryptSymmetricKey");
    try {
        // Retrieve the JWK private key from IndexedDB
        const jwkPrivateKey = await getPrivateKey();
        console.log("JWK Private Key:", JSON.stringify(jwkPrivateKey)); // Log the JWK for debugging

        // Import the private key to the CryptoKey object
        const privateKey = await importPrivateKey(jwkPrivateKey);
        console.log("Private key used for decryption (CryptoKey object): ", privateKey);

        // No need for Base64 conversion since the encrypted key is already an ArrayBuffer

        // Decrypt the symmetric key with the private key
        const decryptedSymKey = await window.crypto.subtle.decrypt(
                {
                    name: "RSA-OAEP",
                    hash: {name: "SHA-256"} // This should match the Java OAEPParameterSpec
                },
                privateKey,
                encryptedSymKey // This is an ArrayBuffer
                );

        console.log("Symmetric key decryption successful.");
        return decryptedSymKey;
    } catch (error) {
        console.error("Failed to decrypt symmetric key with error:", error);
        throw new Error("Decryption failed: " + error.message);
    }
}

