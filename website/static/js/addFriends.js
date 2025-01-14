window.addEventListener('load', function () {
    const messageDiv = document.querySelector('.message');
    if (messageDiv && messageDiv.textContent.trim() !== '') {
        setTimeout(() => {
            messageDiv.innerHTML = '';
            // window.location.href = window.location.pathname;
        }, 3000); 
    }
});