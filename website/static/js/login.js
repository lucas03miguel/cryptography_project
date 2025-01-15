document.getElementById("loginForm").addEventListener("submit", function (event) {
    event.preventDefault();

    const username = document.querySelector("input[name='username']").value;
    const clientCert = localStorage.getItem(`${username}_cert`);

    if (clientCert) {
        const form = document.getElementById("loginForm");
        const input = document.createElement("input");
        input.type = "hidden";
        input.name = `${username}_cert`;
        input.value = clientCert;
        form.appendChild(input);
        form.submit();
    } else {
        const form = document.getElementById("loginForm");
        form.submit();
    }
});
