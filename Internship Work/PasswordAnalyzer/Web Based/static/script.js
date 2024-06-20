// script.js
document.getElementById('generate').addEventListener('click', () => {
    const length = document.getElementById('length').value;
    fetch('/generate', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/x-www-form-urlencoded',
        },
        body: `length=${length}`
    })
    .then(response => response.json())
    .then(data => {
        document.getElementById('password').value = data.password;
    });
});

document.getElementById('analyze-btn').addEventListener('click', () => {
    const password = document.getElementById('analyze').value;
    fetch('/analyze', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/x-www-form-urlencoded',
        },
        body: `password=${password}`
    })
    .then(response => response.json())
    .then(data => {
        document.getElementById('analysis-result').innerText = data.analysis;
    });
});
