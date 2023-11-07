package com.securechatapp;

import java.sql.Timestamp;

/**
 * Simplified message class for chat history functionality.
 */
public class Message {

    private int id; // Unique identifier for the message
    private int senderId; // Sender's user ID
    private int recipientId; // Recipient's user ID
    private String senderUsr; // Recipient's user Username
    private String recipientUsr; // Recipient's user Username
    private String content; // Content of the message
    private Timestamp timestamp; // Timestamp of when the message was sent

    // Constructor
    public Message() {
        
    }

    public Message(int id, int senderId, int recipientId, String senderUsr, String recipientUsr, String content, Timestamp timestamp) {
        this.id = id;
        this.senderId = senderId;
        this.recipientId = recipientId;
        this.senderUsr = senderUsr;
        this.recipientUsr = recipientUsr;
        this.content = content;
        this.timestamp = timestamp;
    }

    // Getters and setters
    public int getId() {
        return id;
    }

    public void setId(int id) {
        this.id = id;
    }

    public int getSenderId() {
        return senderId;
    }

    public void setSenderId(int senderId) {
        this.senderId = senderId;
    }

    public int getRecipientId() {
        return recipientId;
    }

    public void setRecipientId(int recipientId) {
        this.recipientId = recipientId;
    }

    public String getContent() {
        return content;
    }

    public void setContent(String content) {
        this.content = content;
    }

    public Timestamp getTimestamp() {
        return timestamp;
    }

    public void setTimestamp(Timestamp timestamp) {
        this.timestamp = timestamp;
    }
    
    public String getRecipientUsr() {
        return recipientUsr;
    }

    public void setRecipientUsr(String recipientUsr) {
        this.recipientUsr = recipientUsr;
    }
    
      public String getSenderUsr() {
        return senderUsr;
    }

    public void setSenderUsr(String senderUsr) {
        this.senderUsr = senderUsr;
    }
}
