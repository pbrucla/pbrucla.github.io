function adjustFooter() {
    const footer = document.querySelector("footer > .window-container > .window");
    const rem = parseFloat(getComputedStyle(document.querySelector("nav"))["padding-top"]);
    const textHeight = getTextHeight();
    
    const rows = Math.floor((window.innerHeight - rem) / textHeight);
    footer.style.bottom = "unset";
    footer.style.top = `calc(1rem + ${rows - 4} * var(--nav-footer-line-height))`;
}

adjustFooter();
window.addEventListener("resize", () => adjustFooter());
