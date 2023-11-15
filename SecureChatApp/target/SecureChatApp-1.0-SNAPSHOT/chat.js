// JavaScript for Chat Application

// Importing functions from secure.js
import {
encryptForSending,
        decryptForDisplay,
        decryptAndStoreSymKey,
        checkIfPrivateKeyExists,
        decryptPrivateKey,
        doesSymKeyExistForRecipient
        } from './secure.js';
        
document.addEventListener("DOMContentLoaded", function () {
    
    // DOM Elements
    const chatArea = document.getElementById("chat-area");
    const messageInput = document.getElementById("message-input");
    const sendButton = document.getElementById("send-button");
    const usersSidebar = document.getElementById("users-sidebar");
    const currentUserSpan = document.getElementById("current-user");
    
    let  privateKeyPass;
    let  currentConversationId;
    let  currentChatUserId; // The current user's ID you're chatting with 

    // Use window.location.host to automatically adapt to the environment's host and port
    const socket = new WebSocket(`wss://${window.location.host}/SecureChatApp/chat`);    

    // On opening the socket
    socket.onopen = function (event) {
        checkForPrivateKey();
    };

    // On receiving a response from the server
    socket.onmessage = async function (event) {
        if (event.data instanceof Blob) {
            // This is the symmetric key response, handle it separately
            handleSymKeyResponse(event);
        } else {
            // Assume this is JSON data
            try {
                const data = JSON.parse(event.data);
                const handler = messageTypeHandlers[data.type];
                if (handler) {
                    await handler(data);
                } else {
                    console.error('No handler for message type:', data.type);
                }
            } catch (error) {
                console.error('Failed to handle incoming message:', error);
            }
        }
    };

    // On closing the socket
    socket.onclose = function (event) {
        redirectToLogin(); // Redirect to login on WebSocket close
    };

    // On socket error
    socket.onerror = function (event) {
        console.error("WebSocket error observed:", event);
        // Provide user feedback
        alert("A WebSocket error has occurred. Please check the console for more information.");
    };

    // Send Message on Send Button Click and when the Enter key is pressed
    sendButton.addEventListener("click", sendMessage);
    messageInput.addEventListener("keypress", function (event) {
        if (event.key === "Enter") {
            event.preventDefault(); // Prevent default to stop newline insertion
            sendMessage();
        }
    });
    
    // Check if the private key is contained in IndexedDB
    async function checkForPrivateKey() {
        const privateKeyExists = await checkIfPrivateKeyExists();
        if (!privateKeyExists) {
            console.log(`Private key doesn't exist for userid: ${currentUserId}`); // Password input box should be implemented (with hidden text)
            // Prompt the user to input their Private Key Password
            privateKeyPass = window.prompt("Please enter your Private Key Password:", "");
            if (privateKeyPass) {
                await requestPrivateKey(socket);
            }
        }
    }

    // Redirect to the login page
    function redirectToLogin() {
        window.location.href = 'index.html';
    }

    // Function to send message
    async function sendMessage() {
        const message = messageInput.value.trim();
        console.log("Preparing to send currentConversationId", currentConversationId); // In here if currentConversationId == null , prompt the user to select a conversation

        if (message && currentChatUserId && currentConversationId) {
            try {
                const encryptedContent = await encryptForSending(message, currentConversationId); // Call the function to decript message from secure.js

                socket.send(JSON.stringify({ // send the data to the server on the socket declared above
                    type: "message",
                    recipient: currentChatUserId,
                    conversationId: currentConversationId,
                    content: encryptedContent
                }));
                
                // Append the message to the sender's chatbox
                appendMessage({
                    from: 'You',
                    content: message, // Using the original message here since it's for the sender's view
                    isSender: true,
                    conversationId: currentConversationId
                });

                // Clear the input after sending
                messageInput.value = '';
            } catch (error) {
                console.error("Error during message sending:", error);
            }
        }
    }

    /// Function to decrypt (if needed) and append the message to the chat area
    async function appendMessage( { from, content, isSender, conversationId }) {
        if (conversationId !== currentConversationId) {
            return; // If the message is not part of the current conversation, ignore it
        }

        // Check if the content is in the expected encrypted format (IV:ciphertext) 
        if (content.includes(':')) { //to implement a better method to check for encrypted vs plain text
            try {
                // Assume the message is encrypted and attempt to decrypt it
                const decryptedContent = await decryptForDisplay(content, conversationId);
                content = decryptedContent; // Update content to be the decrypted message
            } catch (error) {
                console.error("Decryption error:", error);
                // If decryption fails, display a placeholder instead
                content = '[Encrypted Message]';
            }
        }

        // Append the message to the chat area
        const messageDiv = document.createElement("div");
        messageDiv.classList.add("message", isSender ? "sent" : "received");
        messageDiv.textContent = `${from}: ${content}`;
        chatArea.appendChild(messageDiv);
        chatArea.scrollTop = chatArea.scrollHeight; // Auto-scroll to the newest message
    }

    // Function to switch the chat user and request chat history
    async function switchChatUser(recipientId, username) {
        console.log(`Switching to chat with user ID: ${recipientId}, username: ${username}`);
        currentChatUserId = recipientId;
        updateChatHeader(username);
        setActiveUserButton(recipientId);

        try {
            const symKeyExists = doesSymKeyExistForRecipient(recipientId); // check if the symmetric key exists before requesting the chat history
            console.log("Symmetric key for conversation exists:", symKeyExists);
            if (!symKeyExists) {
                // Request the symmetric key from the server
                console.log("Requesting symmetric key for user ID:", recipientId);
                await requestSymKey(socket, recipientId);
            } else {
                // If the symmetric key is available, request the chat history
                await requestEncryptedHistory(socket, recipientId);
            }
        } catch (error) {
            console.error("Error switching chat user:", error);
        }
    }    

    // Function to update the user list on the sidebar
    function updateUserList(data) {
        usersSidebar.innerHTML = ''; // Clear the current user list
        data.users.forEach(user => {
            if (user.username !== currentUserUsername) {
                const userButton = document.createElement('button');
                userButton.textContent = user.username;
                userButton.classList.add('user-button');
                userButton.dataset.userId = user.id;
                userButton.addEventListener('click', () => switchChatUser(user.id, user.username));
                usersSidebar.appendChild(userButton);
            }
        });
    }

    // Update the chat header with the selected user's username
    function updateChatHeader(username) {
        const chatHeader = document.getElementById('chat-with');
        if (chatHeader) {
            chatHeader.textContent = `Chat with: ${username}`;
        } else {
            console.error('Chat header element not found');
        }
    }

    // Set the active class on the selected user button
    function setActiveUserButton(userId) {
        // Remove active class from all user buttons
        var userButtons = document.getElementsByClassName('user-button');
        Array.from(userButtons).forEach(button => button.classList.remove('active'));
        // Add active class to the selected user button
        var activeButton = usersSidebar.querySelector(`[data-user-id="${userId}"]`);
        if (activeButton) {
            activeButton.classList.add('active');
        }
    }

    // Functions to request data from the server

    // Function to request the symmetric key from the server
    function requestSymKey(socket, userId) {
        // Send the request for the symmetric key to the server
        return new Promise((resolve, reject) => {
            socket.send(JSON.stringify({
                type: "requestSymKey",
                recipientId: userId
            }));
        });
    }

    // Function to request the private key from the server
    function requestPrivateKey(socket) {
        console.log('in requestPrivateKey');
        // Send the request for the symmetric key to the server
        return new Promise((resolve, reject) => {
            socket.send(JSON.stringify({type: "requestPrivateKey"}));
        });
    }

    // Function to request the encrypted chat history from the server
    async function requestEncryptedHistory(socket, userId) {
        return new Promise((resolve, reject) => {
            // Send the request for the chat history
            socket.send(JSON.stringify({type: "requestChatHistory", recipientId: userId}));
        });
    }

    //Functions to handle server responses
    
    // Function to handle the chat history response from the server
    async function handleChatHistoryResponse(data) {

        if (data.conversationId) {
            chatArea.innerHTML = ''; // Clear chat area before appending new messages
            currentConversationId = data.conversationId;
            for (let message of data.messages) {
                try {
                    appendMessage({
                        from: message.senderId === currentUserId ? 'You' : message.sender_username,
                        content: message.content,
                        isSender: message.senderId === currentUserId,
                        conversationId: data.conversationId
                    });
                } catch (error) {
                    console.error("Calling appendMessage from handleChatHistoryResponse error:", error);
                }
            }
        } else {
            console.error('No conversationId received with chat history response.');
        }
    }

    // Handle the incoming binary message for the symmetric key
    async function handleSymKeyResponse(event) {
        // Server sends event.data as a Blob containing the conversation ID and encrypted symmetric key
        const arrayBuffer = await event.data.arrayBuffer();
        const dataView = new DataView(arrayBuffer);

        // Read the conversation ID from the first 4 bytes of the ArrayBuffer
        currentConversationId = dataView.getInt32(0);

        // Extract the encrypted symmetric key which follows the conversation ID
        const encryptedSymKeyBuffer = arrayBuffer.slice(4); // Use 4 for the size of an integer in bytes

        try {
            // Decrypt the symmetric key and store it
            const symKey = await decryptAndStoreSymKey(encryptedSymKeyBuffer, currentConversationId, currentChatUserId, currentUserUsername);

            // Now that the symmetric key is stored, we can proceed to request the chat history
            await requestEncryptedHistory(socket, currentChatUserId);
        } catch (error) {
            console.error("Error handling the symmetric key response:", error);
        }
    }
    
    // Function to handle private key update response from the server
    async function updatePrivateKey(data) {
        console.log('Private key received from the server: ', data);

        const encryptedPrivateKeyBase64 = data.privateKey;
        decryptPrivateKey(encryptedPrivateKeyBase64, privateKeyPass);
    }
    
    // Function to handle a new incoming message
    async function handleMessage(data) {
        console.log("in handleMessage data.conversationId: " + data.conversationId);
        const conversationId = data.conversationId;
        if (!conversationId) {
            console.error("No conversationId provided with message:", data);
            return; // Exit the function if there is no conversationId
        }
        if (currentChatUserId === data.senderId) {
            const isSender = data.senderId === currentUserId;
            appendMessage({
                content: data.content,
                from: isSender ? 'You' : data.senderUsername,
                isSender: isSender,
                conversationId: conversationId
            });
        } else {
            // This message is for a conversation that is not currently active
            const userButton = document.querySelector(`.user-button[data-user-id="${data.senderId}"]`);
            if (userButton && !userButton.classList.contains('flicker')) {
                userButton.classList.add('flicker');
                setTimeout(() => {
                    userButton.classList.remove('flicker'); // Remove flicker after some time
                }, 3000); // Adjust time as needed for flicker effect duration
            }
        }
    }

    // Handlers 
    const messageTypeHandlers = {
        chatHistoryResponse: handleChatHistoryResponse,
        message: handleMessage,
        userListUpdate: updateUserList,
        privateKeyUpdate: updatePrivateKey
    };

    // Close the socket upon closing the page
    window.addEventListener("beforeunload", function () {
        if (socket.readyState === WebSocket.OPEN) {
            socket.close();
        }
    });
});

