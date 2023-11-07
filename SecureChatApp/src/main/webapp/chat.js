// JavaScript for Chat Application

document.addEventListener("DOMContentLoaded", function () {
// DOM Elements
    const chatArea = document.getElementById("chat-area");
    const messageInput = document.getElementById("message-input");
    const sendButton = document.getElementById("send-button");
    const usersSidebar = document.getElementById("users-sidebar");
    const currentUserSpan = document.getElementById("current-user");
    var currentConversationId = null;
    var currentChatUserId = null; // The current user's ID you're chatting with
    var symmetricKeyObject = null;
    // Websocket Initialization
    //var socket = new WebSocket("wss://localhost:8443/SecureChatApp/chat");

    // Determine the protocol to use for WebSocket
    var wsProtocol = window.location.protocol === "https:" ? "wss" : "ws";
    // Use window.location.host to automatically adapt to the environment's host and port
    var socket = new WebSocket(`${wsProtocol}://${window.location.host}/SecureChatApp/chat`);
    // Extract the current user's username from the DOM
    var currentUserUsername = currentUserSpan.textContent.replace('Logged in as: ', '').trim();
    // WebSocket Event Handlers
    socket.onopen = function (event) {
    };
    socket.onmessage = function (event) {
        console.log("Received: " + event.data);
        var data = JSON.parse(event.data);
        handleIncomingData(data);
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

    // Function to send an encrypted message to the server
    async function sendMessage() {
        var message = messageInput.value.trim();
        if (!message) {
            console.error("No message to send.");
            return;
        }
        if (!currentChatUserId) {
            console.error("No currentChatUserId set. Cannot send message.");
            return;
        }
        if (!currentConversationId) {
            console.error("No currentConversationId set. Cannot send message.");
            return;
        }

        // Log the symmetricKeyObject for debugging
        console.log("Symmetric key object before encryption:", symmetricKeyObject);


        // Encrypt the message
        try {
            if (!(symmetricKeyObject instanceof CryptoKey)) {
                throw new Error('symmetricKeyObject is not a CryptoKey instance');
            }
            const encryptedData = await encryptMessage(message, symmetricKeyObject);
            // Convert both the IV and the ciphertext to Base64
            const ivBase64 = arrayBufferToBase64(encryptedData.iv);
            const encryptedContentBase64 = arrayBufferToBase64(encryptedData.ciphertext);
            // Combine IV with the encrypted content
            const combinedContentBase64 = ivBase64 + ':' + encryptedContentBase64;
            // Send the combined IV and encrypted message as Base64
            var messageData = JSON.stringify({
                type: "message",
                recipient: currentChatUserId,
                conversationId: currentConversationId,
                content: combinedContentBase64 // Sending the encrypted content
            });
            socket.send(messageData);
            messageInput.value = ''; // Clear the input field after sending
        } catch (error) {
            console.error("Encryption failed", error);
        }
    }

    // Function to decrypt and append the message to the chat area
    async function appendMessage( { from, content, isSender, conversationId }) {
        if (conversationId !== currentConversationId) {
            console.error("Received message for a different conversation:", conversationId);
            return; // If the message is not part of the current conversation, ignore it
        }

        // Decrypt the message if it's received (not sent by the current user)
        let displayContent = content;
        if (!isSender) {
            // Split the combined IV and encrypted content
            const [ivBase64, encryptedContentBase64] = content.split(':');
            const iv = base64ToArrayBuffer(ivBase64);
            const encryptedContent = base64ToArrayBuffer(encryptedContentBase64);
            try {
                const decryptedData = await decryptMessage({ciphertext: encryptedContent, iv: iv}, symmetricKeyObject);
                displayContent = decryptedData;
            } catch (error) {
                console.error("Decryption failed", error);
                displayContent = "[Encrypted Message]"; // Fallback content
            }
        }

        // Create message element and append to chat area
        const messageDiv = document.createElement("div");
        messageDiv.classList.add("message", isSender ? "sent" : "received");
        const displayFrom = isSender ? "You" : from;
        messageDiv.textContent = `${displayFrom}: ${displayContent}`;
        chatArea.appendChild(messageDiv);
        chatArea.scrollTop = chatArea.scrollHeight; // Auto-scroll to the newest message
    }

    // Update the user list on the sidebar
    function updateUserList(users) {
        // Clear the current user list
        usersSidebar.innerHTML = '';
        // Iterate over the user list and create buttons for each user
        users.forEach(function (user) {
            // Check to avoid adding the current user to the list
            if (user.username !== currentUserUsername) {
                const userButton = document.createElement('button');
                userButton.textContent = user.username;
                userButton.classList.add('user-button');
                userButton.dataset.userId = user.id; // Store the user ID in the button dataset

                // Add an event listener for the click on user button
                userButton.addEventListener('click', function () {
                    switchChatUser(user.id, user.username);
                });
                // Append the user button to the sidebar
                usersSidebar.appendChild(userButton);
            }
        });
    }

    function switchChatUser(userId, username) {
        console.log(`Switching to chat with user ID: ${userId}, username: ${username}`);
        currentChatUserId = userId; // Set the current user you're chatting with
        chatArea.innerHTML = ''; // Clear the chat area
        updateChatHeader(username); // Update the chat header with the new user's name
        setActiveUserButton(userId); // Highlight the active user button
        requestChatHistory(userId); // Make the request for chat history
        if (!symmetricKeyObject) {
            socket.send(JSON.stringify({
                type: "requestChatHistory",
                recipientId: userId,
                needSymKey: true // Add this to indicate you need the symmetric key
            }));
        }
    }


    // Request chat history for the selected user
    function requestChatHistory(userId) {
        socket.send(JSON.stringify({
            type: "requestChatHistory",
            recipientId: userId,
            needSymKey: false
        }));
    }

    // Function to process incoming WebSocket data
    async function handleIncomingData(data) {
        console.log("data received: ", data);
        // Process the message based on its type
        switch (data.type) {
            case 'userListUpdate':
                updateUserList(data.users); // Update the user list
                break;
            case 'message':
                // Check if the conversationId is provided
                if (!data.conversationId) {
                    console.error("No conversationId provided with message:", data);
                    return; // Exit the function if there is no conversationId
                }
                const conversationId = data.conversationId;
                console.log("Setting currentConversationId from message:", conversationId);
                // Log the current chat user ID and the IDs from the message for comparison
                console.log("Current chat user ID:", currentChatUserId);
                console.log("Message from ID:", data.fromId);
                if (currentChatUserId === data.fromId) {
                    currentConversationId = conversationId;
                    const isSender = data.fromId === currentUserId;
                    appendMessage({
                        content: data.content,
                        from: isSender ? 'You' : data.fromUsr,
                        isSender: isSender,
                        conversationId: conversationId
                    });
                } else {
                    console.log("Message is not for the current chat.");
                }
                break;
            case 'chatHistoryResponse':
                console.log("chatHistoryResponse received: ", data);
                // Assuming the server sends a 'conversationId' even if messages are empty
                if (typeof data.conversationId !== 'undefined') {
                    currentConversationId = data.conversationId;
                    console.log("Setting currentConversationId from chat history:", currentConversationId);
                } else if (data.messages.length > 0) {
                    currentConversationId = data.messages[0].conversationId;
                    console.log("Setting currentConversationId from chat history:", currentConversationId);
                } else {
                    console.error('No conversationId received with chat history response.');
                    return;
                }

                // Clear existing messages in the chat area
                chatArea.innerHTML = '';
                console.log("Data before loop: ", data);
                // Now process each message in the history
                data.messages.forEach(message => {
                    const isSender = message.senderId === currentUserId;
                    // Decide whether to use sender's username or recipient's based on who is the sender
                    const usernameDisplay = isSender ? 'You' : message.sender_username;
                    console.log("message.senderId: " + message.senderId);
                    console.log("currentUserId: " + currentUserId);
                    appendMessage({
                        content: message.content,
                        from: usernameDisplay,
                        isSender: isSender,
                        conversationId: currentConversationId
                    });
                });
                break;
            case 'symKeyResponse':
                const encryptedSymKey = data.encryptedSymKey;
                try {
                    const decryptedSymKey = await decryptSymmetricKey(encryptedSymKey);
                    symmetricKeyObject = await importSymmetricKey(decryptedSymKey);
                    console.log("Symmetric key object after import:", symmetricKeyObject);
                } catch (error) {
                    console.error("Failed to decrypt symmetric key:", error);
                    // Handle decryption failure appropriately
                }
                break;

            default:
                console.error('Unknown message type received:', data.type);
        }
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


});
