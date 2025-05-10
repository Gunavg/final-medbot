document.addEventListener("DOMContentLoaded", function () {
    const chatInput = document.querySelector("#chat-input");
    const sendButton = document.querySelector("#send-message");
    const chatMessages = document.querySelector("#chat-messages");

    function addMessage(content, isUser) {
        const messageDiv = document.createElement("div");
        messageDiv.classList.add("chat-message");
        messageDiv.classList.add(isUser ? "user" : "bot");
        messageDiv.textContent = content;
        chatMessages.appendChild(messageDiv);
        chatMessages.scrollTop = chatMessages.scrollHeight;
    }

    function getBotResponse(message) {
        const lowerMessage = message.toLowerCase();
        if (lowerMessage.includes("symptom")) {
            return "Please go to the Symptom Checker page to select your symptoms.";
        } else if (lowerMessage.includes("disease")) {
            return "I can help predict diseases based on symptoms. Visit the Symptom Checker page.";
        } else if (lowerMessage.includes("help")) {
            return "I'm here to assist! You can ask about symptoms, diseases, or navigate to the Symptom Checker.";
        } else {
            return "I'm not sure how to respond to that. Try asking about symptoms or diseases!";
        }
    }

    sendButton.addEventListener("click", () => {
        const message = chatInput.value.trim();
        if (message) {
            addMessage(message, true);
            const response = getBotResponse(message);
            setTimeout(() => addMessage(response, false), 500);
            chatInput.value = "";
        }
    });

    chatInput.addEventListener("keypress", (e) => {
        if (e.key === "Enter") {
            sendButton.click();
        }
    });
});