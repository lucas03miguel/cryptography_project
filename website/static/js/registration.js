const passwordInput = document.querySelector('input[name="password"]');
const passwordHelp = document.getElementById('passwordHelp');
const form = document.querySelector('form');

passwordInput.addEventListener('input', function () {
    const password = passwordInput.value;

    if (password === "") {
        passwordHelp.innerHTML = "";
        return;
    }

    const rules = [
        { regex: /.{8,}/, message: "At least 8 characters" },
        { regex: /[A-Z]/, message: "One uppercase letter" },
        { regex: /[a-z]/, message: "One lowercase letter" },
        { regex: /[@$!%*?&]/, message: "One special character (@$!%*?&)" }
    ];

    const errors = rules.filter(rule => !rule.regex.test(password)).map(rule => rule.message);

    if (errors.length === 0) {
        passwordHelp.style.color = "green";
        passwordHelp.innerHTML = `<div style="margin-left: 1.5rem; text-align: left;">Password is strong!</div>`;
        passwordInput.setCustomValidity("");
    } else {
        passwordHelp.style.color = "red";
        passwordHelp.innerHTML = `
            <div style="margin-left: 1.5rem; text-align: left;">Your password must include:</div>
            <ul style="text-align: left;">
                ${errors.map(error => `<li>${error}</li>`).join("")}
            </ul>
        `;
        passwordInput.setCustomValidity("Password must meet the strength criteria.");
    }
});


form.addEventListener('submit', function (event) {
    if (passwordHelp.style.color !== "green") {
        event.preventDefault();
        alert("Please ensure your password meets the required criteria.");
    }
});

const messageTd = document.getElementById('message-td');
const inputs = document.querySelectorAll('input');
inputs.forEach(input => {
    input.addEventListener('input', function () {
        if (messageTd && messageTd.innerHTML.trim() !== '') {
            messageTd.innerHTML = '';
        }
    });
});
