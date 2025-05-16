document.addEventListener('DOMContentLoaded', function() {
    // Dark mode toggle
    const darkModeToggle = document.querySelector('.dark-mode-toggle');
    if (darkModeToggle) {
        darkModeToggle.addEventListener('click', function() {
            document.body.classList.toggle('dark-mode');
            localStorage.setItem('darkMode', document.body.classList.contains('dark-mode'));
        });
    } else {
        console.warn('Dark mode toggle not found.');
    }

    // Load dark mode preference
    if (localStorage.getItem('darkMode') === 'true') {
        document.body.classList.add('dark-mode');
    }

    // Menu toggle
    const menuIcon = document.querySelector('.menu-icon');
    const navMenu = document.querySelector('.nav-menu');
    if (menuIcon && navMenu) {
        // Remove existing listeners to prevent duplicates
        const newMenuIcon = menuIcon.cloneNode(true);
        menuIcon.parentNode.replaceChild(newMenuIcon, menuIcon);
        
        newMenuIcon.addEventListener('click', function(event) {
            event.preventDefault();
            event.stopPropagation();
            navMenu.classList.toggle('active');
            console.log('Menu toggled:', navMenu.classList.contains('active') ? 'Opened' : 'Closed');
        });

        // Close menu when clicking outside
        document.addEventListener('click', function(event) {
            if (!navMenu.contains(event.target) && !newMenuIcon.contains(event.target) && navMenu.classList.contains('active')) {
                navMenu.classList.remove('active');
                console.log('Menu closed: Clicked outside');
            }
        });
    } else {
        console.error('Menu icon or nav menu not found:', { menuIcon, navMenu });
    }

    // Password toggle functionality
    function setupPasswordToggle(toggleId, inputId) {
        const toggle = document.getElementById(toggleId);
        const input = document.getElementById(inputId);
        if (toggle && input) {
            toggle.addEventListener('click', function() {
                const type = input.getAttribute('type') === 'password' ? 'text' : 'password';
                input.setAttribute('type', type);
                this.classList.toggle('fa-eye');
                this.classList.toggle('fa-eye-slash');
                console.log(`Password toggle for ${inputId}: ${type}`);
            });
        } else {
            console.warn(`Password toggle setup failed: toggle=${toggle}, input=${input}`);
        }
    }

    // Initialize password toggles
    setupPasswordToggle('toggle-password', 'password');
    setupPasswordToggle('toggle-security-question1', 'security_question1');
    setupPasswordToggle('toggle-security-question2', 'security_question2');
    setupPasswordToggle('toggle-security-question3', 'security_question3');
    setupPasswordToggle('toggle-security-answer1', 'security_answer1');
    setupPasswordToggle('toggle-security-answer2', 'security_answer2');
    setupPasswordToggle('toggle-security-answer3', 'security_answer3');
    setupPasswordToggle('toggle-confirm-password', 'confirm_password');

    // Symptom progress bar
    const checkboxes = document.querySelectorAll('.symptom-checkbox input[type="checkbox"]');
    const symptomLimit = 20; // Increased to 20 symptoms
    const progressBarFill = document.querySelector('.progress-bar-fill');
    
    function updateProgressBar() {
        const checkedCount = document.querySelectorAll('.symptom-checkbox input[type="checkbox"]:checked').length;
        const progressPercentage = (checkedCount / symptomLimit) * 100; // 5% per symptom
        if (progressBarFill) {
            progressBarFill.style.width = `${progressPercentage}%`;
        }
    }

    checkboxes.forEach(checkbox => {
        checkbox.addEventListener('change', function() {
            const checkedCount = document.querySelectorAll('.symptom-checkbox input[type="checkbox"]:checked').length;
            if (checkedCount > symptomLimit) {
                this.checked = false;
                alert(`You can select up to ${symptomLimit} symptoms.`);
            }
            updateProgressBar();
        });
    });

    // Initialize progress bar
    updateProgressBar();
});