// Support Chat Widget Logic

let chatState = {
    isOpen: false,
    messageCount: 0,
    botResponseIndex: 0,
    isTyping: false,
    hasGreeted: false
};

const chatResponses = [
    "Thank you for contacting Bank of America Support.",
    "Please hold while we connect you to an agent...",
    "Connecting...",
    "How may I assist you today?",
    "I understand your concern. Let me look into that for you...",
    "Can you please provide your account number?",
    "Thank you for that information. One moment please...",
    "I'm checking our system now...",
    "For security purposes, can you verify your date of birth?",
    "I see. Let me escalate this to our technical team...",
    "This may take a few moments to process...",
    "Have you tried logging out and back in?",
    "Can you describe the issue in more detail?",
    "I'm still reviewing your account. Please hold...",
    "Our system is running a bit slow today. Thank you for your patience...",
    "Let me transfer you to a specialist who can better assist you...",
    "I apologize for the inconvenience. We're experiencing high volume today..."
];

const stallingMessages = [
    "Please hold...",
    "One moment...",
    "Checking...",
    "Loading your account information...",
    "Still processing...",
    "Almost there...",
    "Thank you for waiting..."
];

const endingMessages = [
    "I'm sorry, but I'm experiencing technical difficulties.",
    "The system is not responding. Can you please try again later?",
    "Our chat session has timed out. Please call 1 (800) 432-1000 for immediate assistance.",
    "Agent has left the chat."
];

function toggleChat() {
    const chatWindow = document.getElementById('chat-window');
    const chatButton = document.getElementById('chat-button');
    const badge = document.querySelector('.chat-notification-badge');
    
    chatState.isOpen = !chatState.isOpen;
    
    if (chatState.isOpen) {
        chatWindow.style.display = 'flex';
        chatButton.style.display = 'none';
        if (badge) badge.style.display = 'none';
        
        // Send greeting sequence if first time
        if (!chatState.hasGreeted) {
            chatState.hasGreeted = true;
            setTimeout(() => sendBotResponse("Thank you for contacting Bank of America Support."), 2000);
            setTimeout(() => sendBotResponse("Please hold while we connect you to an agent..."), 5000);
            setTimeout(() => showTypingIndicator(), 13000);
            setTimeout(() => {
                hideTypingIndicator();
                sendBotResponse("How may I assist you today?");
            }, 18000);
        }
    } else {
        chatWindow.style.display = 'none';
        chatButton.style.display = 'flex';
    }
}

function sendMessage(event) {
    event.preventDefault();
    
    const input = document.getElementById('chat-input');
    const message = input.value.trim();
    
    if (message === '') return;
    
    // Add user message
    addMessage(message, 'user');
    input.value = '';
    
    chatState.messageCount++;
    
    // Check if we should end the chat
    if (chatState.messageCount >= 10) {
        setTimeout(() => {
            const endMsg = endingMessages[Math.floor(Math.random() * endingMessages.length)];
            sendBotResponse(endMsg);
        }, getRandomDelay(3000, 8000));
        return;
    }
    
    // Bot response with random delay
    setTimeout(() => {
        showTypingIndicator();
        
        setTimeout(() => {
            hideTypingIndicator();
            
            // Randomly choose between actual response or stalling
            const useStalling = Math.random() < 0.3;
            
            if (useStalling) {
                const stallingMsg = stallingMessages[Math.floor(Math.random() * stallingMessages.length)];
                sendBotResponse(stallingMsg);
                
                // Follow up with real response
                setTimeout(() => {
                    showTypingIndicator();
                    setTimeout(() => {
                        hideTypingIndicator();
                        sendRandomBotResponse();
                    }, getRandomDelay(3000, 6000));
                }, getRandomDelay(2000, 4000));
            } else {
                sendRandomBotResponse();
            }
        }, getRandomDelay(3000, 10000));
    }, 1000);
}

function sendRandomBotResponse() {
    const response = chatResponses[chatState.botResponseIndex % chatResponses.length];
    chatState.botResponseIndex++;
    sendBotResponse(response);
}

function sendBotResponse(text) {
    addMessage(text, 'bot');
}

function addMessage(text, sender) {
    const chatBody = document.getElementById('chat-messages');
    const messageDiv = document.createElement('div');
    messageDiv.className = `chat-message ${sender}-message`;
    
    const now = new Date();
    const timeStr = now.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
    
    messageDiv.innerHTML = `
        <div class="message-content">${text}</div>
        <small class="message-time">${timeStr}</small>
    `;
    
    chatBody.appendChild(messageDiv);
    chatBody.scrollTop = chatBody.scrollHeight;
}

function showTypingIndicator() {
    if (chatState.isTyping) return;
    chatState.isTyping = true;
    
    const chatBody = document.getElementById('chat-messages');
    const typingDiv = document.createElement('div');
    typingDiv.className = 'chat-message bot-message';
    typingDiv.id = 'typing-indicator';
    typingDiv.innerHTML = `
        <div class="typing-indicator">
            <span></span>
            <span></span>
            <span></span>
        </div>
    `;
    
    chatBody.appendChild(typingDiv);
    chatBody.scrollTop = chatBody.scrollHeight;
}

function hideTypingIndicator() {
    const typingDiv = document.getElementById('typing-indicator');
    if (typingDiv) {
        typingDiv.remove();
    }
    chatState.isTyping = false;
}

function getRandomDelay(min, max) {
    return Math.floor(Math.random() * (max - min + 1)) + min;
}

// Update wait time periodically
setInterval(() => {
    const waitTimes = ['3 minutes', '5 minutes', '7 minutes', '10 minutes', '12 minutes'];
    const waitTimeElem = document.getElementById('wait-time');
    if (waitTimeElem) {
        waitTimeElem.textContent = waitTimes[Math.floor(Math.random() * waitTimes.length)];
    }
}, 15000);

