function scrollToBottom() {
    const chatBox = document.querySelector(".chat-box");
    chatBox.scrollTop = chatBox.scrollHeight;
}

// Garante que o scroll vai para o fim ao carregar a página
window.onload = scrollToBottom;

// Opcional: Garante que o scroll vai para o fim ao adicionar novas mensagens
const observer = new MutationObserver(scrollToBottom);
const chatBox = document.querySelector(".chat-box");
observer.observe(chatBox, { childList: true });
