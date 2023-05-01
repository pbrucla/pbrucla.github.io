// Credits: modified from https://codepen.io/atunnecliffe/pen/BaZyLR

const textarea = document.getElementById("term");
const load = document.getElementById("load");
const text = "welcome to psi beta rho";
const hexdump = "  2a 2a 2a 2a 2a 2a 2a 2a  2a 2a 2a 2a 2a 2a 2a 2a  |****************|";

if(!matchMedia("(prefers-reduced-motion)").matches && window.localStorage.getItem("visited") === null) {
    load.style.display = "initial";
    runner(0);
}

function runner(i) {
    textarea.append(text.charAt(i));
    i++;
    setTimeout(
        () => {
            if (i < text.length) {
                runner(i);
            } else {
                textarea.append("\n");
                setTimeout(() => feedbacker(0), 1000);
            }
        },
        // prompt typing speed (in ms)
        Math.floor(Math.random() * 200) + 1
    );
}

function feedbacker(i) {
    if (i == 8) {
        textarea.innerHTML += "00000080  2a 2a <span style='color:#FFBD3F'>50 73 69 20 42 65  74 61 20 52 68 6F</span> 2a 2a  |**<span style='color:#FFBD3F'>Psi Beta Rho</span>**|<br>";
    } else if (i == 9) {
        textarea.innerHTML += "00000090  2a 2a 2a 2a 2a 2a 2a <span style='color:#F44D89'>61  74 20 55 43 4C 41</span> 2a 2a  |*******<span style='color:#F44D89'>at UCLA</span>**|<br>";
    } else {
        textarea.append(leftPad(Number(i).toString(16).toUpperCase(), 7, '0') + '0' + hexdump + "\n");
    }
    
    // scrolling not necessary
    // window.scrollTo(0, document.body.scrollHeight);
    
    i++;
    // output speed (in ms)
    let time = Math.floor(Math.random() * 4) + 1;
    setTimeout(
        () => {
            let textHeight = getTextHeight();
            let paddingHeight = parseFloat(getComputedStyle(load)["padding"]) * 2;
            if (i < 71 && i < (window.innerHeight - paddingHeight) / textHeight - 3) {
                // stop once screen is filled
                feedbacker(i);
            } else {
                // clear splash screen and show Home page
                textarea.append("Starting now...\n");
                setTimeout(
                    () => {
                        load.style.animation = "1s linear both fade-out";
                        setTimeout(() => load.style.display = "none", 1000);
                    },
                    2000
                );
                window.localStorage.setItem('visited', true);
            }
        },
        time
    );
}

function leftPad(content, len, pad=' ') {
    if (content.length >= len) return content;
    return pad.repeat(len - content.length) + content;
}

function getTextHeight() {
    return document.getElementById("splash-hack-zero-for-reference").clientHeight;
}
