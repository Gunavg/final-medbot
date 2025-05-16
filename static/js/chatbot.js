document.addEventListener("DOMContentLoaded", function () {
    const chatInput = document.querySelector("#chat-input");
    const sendButton = document.querySelector("#send-message");
    const chatMessages = document.querySelector("#chat-messages");

    function addMessage(content, isUser) {
        const messageDiv = document.createElement("div");
        messageDiv.classList.add("chat-message", isUser ? "user" : "bot");
        messageDiv.textContent = content;
        chatMessages.appendChild(messageDiv);
        chatMessages.scrollTop = chatMessages.scrollHeight;
    }

    function sendMessage() {
        const message = chatInput.value.trim();
        if (!message) return;
        addMessage(message, true);
        fetch('/chatbot_response', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ message })
        })
        .then(response => {
            if (!response.ok) throw new Error('Network response was not ok');
            return response.json();
        })
        .then(data => {
            setTimeout(() => addMessage(data.response, false), 500);
        })
        .catch(error => {
            console.error('Error:', error);
            addMessage("Sorry, something went wrong. Please try again.", false);
        });
        chatInput.value = "";
    }

    sendButton.addEventListener("click", sendMessage);
    chatInput.addEventListener("keypress", (e) => {
        if (e.key === "Enter") sendMessage();
    });

    // Initial welcome message
    addMessage("Hello! I'm MedBot. How can I assist you today? Try asking about symptoms, diseases, or your dashboard.", false);
});