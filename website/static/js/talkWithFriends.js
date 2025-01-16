function scrollToBottom() {
    const chatBox = document.querySelector(".chat-box");
    chatBox.scrollTop = chatBox.scrollHeight;
}


window.onload = scrollToBottom;


const observer = new MutationObserver(scrollToBottom);
const chatBox = document.querySelector(".chat-box");
observer.observe(chatBox, { childList: true });
