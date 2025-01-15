document.getElementById("loginForm").addEventListener("submit", function (event) {
    event.preventDefault();

    const clientCert = localStorage.getItem("clientCert");
    console.log(clientCert);
    console.log("clientCert");
    if (clientCert) {
        const form = document.getElementById("loginForm");
        const input = document.createElement("input");
        input.type = "hidden";
        input.name = "clientCert";
        input.value = clientCert;
        form.appendChild(input);
        form.submit();
    }
});