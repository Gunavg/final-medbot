document.addEventListener("DOMContentLoaded", function () {
    console.log("Script loaded.");

    const form = document.querySelector("#symptom-form");
    const submitBtn = document.querySelector("button[type='submit']");
    const symptomInputs = document.querySelectorAll("input[name='symptoms']");
    const countDisplay = document.querySelector("#symptom-count");
    const searchBox = document.querySelector("#symptom-search");
    const followUpContainer = document.querySelector("#follow-up-questions");
    const toggleThemeBtn = document.createElement("button");

    // Add theme toggle button
    toggleThemeBtn.textContent = "🌙 Toggle Dark/Light Mode";
    toggleThemeBtn.style.marginTop = "10px";
    form.appendChild(toggleThemeBtn);

    toggleThemeBtn.addEventListener("click", () => {
        document.body.classList.toggle("dark-mode");
        localStorage.setItem("theme", document.body.classList.contains("dark-mode") ? "dark" : "light");
    });

    if (localStorage.getItem("theme") === "dark") {
        document.body.classList.add("dark-mode");
    }

    // Update selected symptom count
    function updateCount() {
        const count = document.querySelectorAll("input[name='symptoms']:checked").length;
        countDisplay.textContent = `Selected symptoms: ${count}`;
        fetchFollowUpQuestions();
    }

    symptomInputs.forEach(input => {
        input.addEventListener("change", updateCount);
    });

    updateCount();

    // Live symptom search filter
    searchBox.addEventListener("input", () => {
        const query = searchBox.value.toLowerCase();
        symptomInputs.forEach(input => {
            const label = input.nextSibling.textContent.trim().toLowerCase();
            input.parentElement.style.display = label.includes(query) ? "" : "none";
        });
    });

    // Fetch follow-up questions
    function fetchFollowUpQuestions() {
        const selectedSymptoms = Array.from(document.querySelectorAll("input[name='symptoms']:checked")).map(input => input.value);
        fetch('/get_follow_up', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ symptoms: selectedSymptoms })
        })
        .then(response => response.json())
        .then(questions => {
            followUpContainer.innerHTML = '';
            if (questions.length > 0) {
                const heading = document.createElement('h3');
                heading.textContent = 'Follow-up Questions';
                followUpContainer.appendChild(heading);
            }
            questions.forEach((q, index) => {
                const div = document.createElement('div');
                div.innerHTML = `
                    <label>${q.question}</label><br>
                    <input type="text" name="follow_up_answers" placeholder="Your answer..." required>
                `;
                followUpContainer.appendChild(div);
            });
        });
    }

    // Confirm before submit
    form.addEventListener("submit", function (e) {
        const confirmSubmit = confirm("Are you sure you want to predict?");
        if (!confirmSubmit) {
            e.preventDefault();
        } else {
            submitBtn.disabled = true;
            submitBtn.textContent = "Predicting...";
        }
    });
});