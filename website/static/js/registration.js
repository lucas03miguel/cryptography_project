// Real-time password validation
const passwordInput = document.querySelector('input[name="password"]');
const passwordHelp = document.getElementById('passwordHelp');
const form = document.getElementById('registrationForm');

passwordInput.addEventListener('input', function () {
    const password = passwordInput.value;

    // Clear validation message if password is empty
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
        passwordHelp.innerHTML = "Password is strong!";
    } else {
        passwordHelp.style.color = "red";
        passwordHelp.innerHTML = `
            <div style="margin-left: 1.5rem; text-align: left;">Your password must include:</div>
            <ul style="text-align: left;">
                ${errors.map(error => `<li>${error}</li>`).join("")}
            </ul>
        `;
    }
});

// Form submit validation
form.addEventListener('submit', function (event) {
    if (passwordInput.value === "" || passwordHelp.style.color === "red") {
        // Prevent form submission
        event.preventDefault();

        passwordInput.setCustomValidity("Password is required and must meet the strength criteria.");
        passwordInput.reportValidity();
    } else {
        passwordInput.setCustomValidity(""); 
    }
});

const inputs = document.querySelectorAll('input');
inputs.forEach(input => {
    input.addEventListener('input', function () {
        input.classList.remove('input-error', 'input-success');
    });
});