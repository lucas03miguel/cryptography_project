document.getElementById("loginForm").addEventListener("submit", function (event) {
    event.preventDefault();

    const username = document.querySelector("input[name='username']").value;
    const clientCert = localStorage.getItem(`${username}_cert`);

    console.log(`Username: ${username}`);
    console.log(`Certificado: ${clientCert}`);

    if (clientCert) {
        const form = document.getElementById("loginForm");
        const input = document.createElement("input");
        input.type = "hidden";
        input.name = `${username}_cert`;
        input.value = clientCert;
        form.appendChild(input);
        form.submit();
    }
});
