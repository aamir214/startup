// ===== GSAP Animated Navbar =====
(function () {
    const nav = document.querySelector('nav.main-nav');
    if (!nav) return;

    const ul = nav.querySelector('ul');
    const buttons = ul.querySelectorAll('li button');

    // Create the animated underline element
    const activeEl = document.createElement('div');
    activeEl.classList.add('active-element');
    ul.appendChild(activeEl);

    // Section mapping: button text -> section selector
    const sectionMap = {
        'Home': '.scan',
        'Scanner': '.scan',
        'About': '#about',
        'Fix Vulnerabilities': '#fix',
        'Contact': '#contact',
    };

    function moveUnderline(button) {
        const li = button.parentElement;
        const liRect = li.getBoundingClientRect();
        const ulRect = ul.getBoundingClientRect();

        const offsetLeft = liRect.left - ulRect.left;
        const targetWidth = liRect.width;

        // Show the underline
        activeEl.style.setProperty('--active-element-show', '1');

        // Use GSAP if available, else fallback to CSS transition
        if (typeof gsap !== 'undefined') {
            gsap.to(activeEl, {
                left: offsetLeft + 'px',
                width: targetWidth + 'px',
                duration: 0.4,
                ease: 'power2.out',
            });
        } else {
            activeEl.style.transition = 'left 0.4s ease, width 0.4s ease';
            activeEl.style.left = offsetLeft + 'px';
            activeEl.style.width = targetWidth + 'px';
        }
    }

    function setActive(clickedButton) {
        // Remove active from all
        ul.querySelectorAll('li').forEach((li) => li.classList.remove('active'));

        // Set active on clicked
        clickedButton.parentElement.classList.add('active');

        // Animate underline
        moveUnderline(clickedButton);
    }

    // Click handlers
    buttons.forEach((btn) => {
        btn.addEventListener('click', () => {
            setActive(btn);

            const sectionSelector = sectionMap[btn.textContent.trim()];
            if (sectionSelector) {
                const section = document.querySelector(sectionSelector);
                if (section) {
                    section.scrollIntoView({ behavior: 'smooth' });
                }
            }
        });
    });

    // Initialize: set active on the first (Home) button
    const firstActive = ul.querySelector('li.active button') || buttons[0];
    if (firstActive) {
        // Small delay to let layout settle
        setTimeout(() => moveUnderline(firstActive), 100);
    }

    // Recalculate on resize
    window.addEventListener('resize', () => {
        const current = ul.querySelector('li.active button');
        if (current) moveUnderline(current);
    });
})();
