// ===== Custom Cursor =====
(function () {
    // Skip on touch devices
    if ('ontouchstart' in window || navigator.maxTouchPoints > 0) return;

    const dot = document.querySelector('.cursor-dot');
    const ring = document.querySelector('.cursor-ring');
    if (!dot || !ring) return;

    let mouseX = 0, mouseY = 0;
    let ringX = 0, ringY = 0;

    // Track mouse position
    document.addEventListener('mousemove', (e) => {
        mouseX = e.clientX;
        mouseY = e.clientY;

        // Dot follows immediately
        dot.style.left = mouseX + 'px';
        dot.style.top = mouseY + 'px';
        dot.style.opacity = '1';
        ring.style.opacity = '1';
    });

    // Ring follows with smooth delay
    function animateRing() {
        ringX += (mouseX - ringX) * 0.15;
        ringY += (mouseY - ringY) * 0.15;

        ring.style.left = ringX + 'px';
        ring.style.top = ringY + 'px';

        requestAnimationFrame(animateRing);
    }
    animateRing();

    // Hover effect on interactive elements
    const interactiveSelectors = 'a, button, input, select, textarea, [role="button"]';

    document.addEventListener('mouseover', (e) => {
        if (e.target.closest(interactiveSelectors)) {
            dot.classList.add('hover');
            ring.classList.add('hover');
        }
    });

    document.addEventListener('mouseout', (e) => {
        if (e.target.closest(interactiveSelectors)) {
            dot.classList.remove('hover');
            ring.classList.remove('hover');
        }
    });

    // Hide cursor when leaving window
    document.addEventListener('mouseleave', () => {
        dot.style.opacity = '0';
        ring.style.opacity = '0';
    });

    document.addEventListener('mouseenter', () => {
        dot.style.opacity = '1';
        ring.style.opacity = '1';
    });
})();
