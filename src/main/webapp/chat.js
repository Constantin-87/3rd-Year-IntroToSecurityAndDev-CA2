// JavaScript for Chat Application
import {
encryptForSending,
        decryptForDisplay,
        decryptAndStoreSymKey,
        conversationData
        } from './secure.js';
document.addEventListener("DOMContentLoaded", function () {
// DOM Elements
    const chatArea = document.getElementById("chat-area");
    const messageInput = document.getElementById("message-input");
    const sendButton = document.getElementById("send-button");
    const usersSidebar = document.getElementById("users-sidebar");
    const currentUserSpan = document.getElementById("current-user");

    var currentConversationId = null;
    var currentChatUserId = null; // The current user's ID you're chatting with 

    // Determine the protocol to use for WebSocket
    var wsProtocol = window.location.protocol === "https:" ? "wss" : "ws";
    // Use window.location.host to automatically adapt to the environment's host and port
    var socket = new WebSocket(`${wsProtocol}://${window.location.host}/SecureChatApp/chat`);
    // Extract the current user's username from the DOM
    var currentUserUsername = currentUserSpan.textContent.replace('Logged in as: ', '').trim();
    // WebSocket Event Handlers

    socket.onopen = function (event) {
    };

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


    socket.onclose = function (event) {
        redirectToLogin(); // Redirect to login on WebSocket close
    };

    socket.onerror = function (event) {
        console.error("WebSocket error observed:", event);
        // Provide user feedback
        alert("A WebSocket error has occurred. Please check the console for more information.");
    };

    // Send Message on Send Button Click
    sendButton.addEventListener("click", sendMessage);
    // Send message when the Enter key is pressed
    messageInput.addEventListener("keypress", function (event) {
        if (event.key === "Enter") {
            event.preventDefault(); // Prevent default to stop newline insertion
            sendMessage();
        }
    });

    // Redirect to the login page
    function redirectToLogin() {
        window.location.href = 'index.html';
    }

    // Function to send an encrypted message
    async function sendMessage() {

        const message = messageInput.value.trim();
        console.log("Preparing to send message", message);
        console.log("Preparing to send currentChatUserId", currentChatUserId);
        console.log("Preparing to send currentConversationId", currentConversationId);
        if (message && currentChatUserId && currentConversationId) {
            try {
                const encryptedContent = await encryptForSending(message, currentConversationId);
                console.log("Encrypted message ready to be sent:", encryptedContent);

                socket.send(JSON.stringify({
                    type: "message",
                    recipient: currentChatUserId,
                    conversationId: currentConversationId,
                    content: encryptedContent
                }));
                // Append the message to the sender's chatbox
                appendMessage({
                    from: 'You', // Assuming you want to label the message as 'You'
                    content: message, // Use the original message here since it's for the sender's view
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
            console.error("Received message for a different conversation:", conversationId);
            return; // If the message is not part of the current conversation, ignore it
        }

        // Check if the content is in the expected encrypted format (IV:ciphertext)
        if (content.includes(':')) {
            try {
                // Assume the message is encrypted and attempt to decrypt it
                const decryptedContent = await decryptForDisplay(content, conversationId);
                console.log("Message decrypted and ready to append:", decryptedContent);
                content = decryptedContent; // Update content to be the decrypted message
            } catch (error) {
                console.error("Decryption error:", error);
                // If decryption fails, display a placeholder instead
                content = '[Encrypted Message]';
            }
        } else {
            console.log("Message is not encrypted, appending directly.");
        }

        // Append the message to the chat area
        const messageDiv = document.createElement("div");
        messageDiv.classList.add("message", isSender ? "sent" : "received");
        messageDiv.textContent = `${from}: ${content}`;
        chatArea.appendChild(messageDiv);
        chatArea.scrollTop = chatArea.scrollHeight; // Auto-scroll to the newest message
    }


    // Function to append a placeholder when decryption fails
    function appendMessagePlaceholder(from, isSender) {
        const messageDiv = document.createElement("div");
        messageDiv.classList.add("message", isSender ? "sent" : "received");
        messageDiv.textContent = `${from}: [Encrypted Message]`;
        chatArea.appendChild(messageDiv);
        chatArea.scrollTop = chatArea.scrollHeight; // Auto-scroll to the newest message
    }




    // Function to switch the chat user and fetch the encrypted chat history
    async function switchChatUser(userId, username) {
        console.log(`Switching to chat with user ID: ${userId}, username: ${username}`);
        currentChatUserId = userId;
        updateChatHeader(username);
        setActiveUserButton(userId);

        try {
            // Check if symmetric key needs to be requested
            const keyExists = conversationData.has(userId);
            if (!keyExists) {
                // Request the symmetric key from the server
                console.log("Requesting symmetric key for user ID:", userId );
                await requestSymKey(socket, userId);
            } else {
                // If the symmetric key is available, request the chat history
                await requestEncryptedHistory(socket, userId);
            }
        } catch (error) {
            console.error("Error switching chat user:", error);
        }
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

    // Function to request the symmetric key from the server
    function requestSymKey(socket, userId) {
        console.log('in requestSymKey, userId: ', userId);
        // Send the request for the symmetric key to the server
        socket.send(JSON.stringify({
            type: "requestSymKey",
            recipientId: userId
        }));
    }

    // Function to request the encrypted chat history from the server
    async function requestEncryptedHistory(socket, userId) {
        return new Promise((resolve, reject) => {
            // Send the request for the chat history
            socket.send(JSON.stringify({type: "requestChatHistory", recipientId: userId}));
        });
    }

    async function handleChatHistoryResponse(data) {

        if (data.conversationId) {
            chatArea.innerHTML = ''; // Clear chat area before appending new messages
            currentConversationId = data.conversationId;
            for (let message of data.messages) {
                try {
                    appendMessage({
                        from: message.senderId === currentUserId ? 'You' : message.sender_username,
                        content: message.content, // this should be the decrypted content
                        isSender: message.senderId === currentUserId,
                        conversationId: data.conversationId
                    });
                } catch (error) {
                    console.error("appendMessage error:", error);
                    appendMessagePlaceholder(message.sender_username, message.senderId === currentUserId);
                }
            }
        } else {
            console.error('No conversationId received with chat history response.');
        }
    }

    // Handle the incoming binary message for the symmetric key
    async function handleSymKeyResponse(event) {
        console.log('in handleSymKeyResponse, data: ', event.data);
        // Assume event.data is a Blob containing the conversation ID and encrypted symmetric key
        const arrayBuffer = await event.data.arrayBuffer();
        const dataView = new DataView(arrayBuffer);

        // Read the conversation ID from the first 4 bytes of the ArrayBuffer
        currentConversationId = dataView.getInt32(0);
        console.log('in handleSymKeyResponse, data: ', currentConversationId);

        // Extract the encrypted symmetric key which follows the conversation ID
        const encryptedSymKeyBuffer = arrayBuffer.slice(4); // Use 4 for the size of an integer in bytes

        try {
            // Decrypt the symmetric key and store it
            const symKey = await decryptAndStoreSymKey(encryptedSymKeyBuffer, currentConversationId);

            // Now that the symmetric key is stored, you can proceed to request the chat history
            await requestEncryptedHistory(socket, currentChatUserId, currentChatUserId);
        } catch (error) {
            console.error("Error handling the symmetric key response:", error);
            // Handle errors (e.g., alert the user, retry the operation, etc.)
        }
    }

    const messageTypeHandlers = {
        chatHistoryResponse: handleChatHistoryResponse,
        message: handleMessage,
        userListUpdate: updateUserList
    };


});

