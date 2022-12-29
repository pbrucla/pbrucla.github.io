// Credits: modified from https://codepen.io/atunnecliffe/pen/BaZyLR

var textarea = $('.term');
var text = 'welcome to psi beta rho';
var i = 0;

runner();

function runner() {
    textarea.append(text.charAt(i));
    i++;
    setTimeout(
        function () {
            if (i < text.length)
                runner();
            else {
                textarea.append("<br>")
                i = 0;
                setTimeout(function () { feedbacker(); }, 1000);
            }
        }, Math.floor(Math.random() * 200) + 1); // prompt typing speed (in ms)
}

var time = 1;
function feedbacker() {
    if (i == 8) {
        textarea.append("00000080  2a 2a <span style='color:#FFBD3F'>50 73 69 20 42 65  74 61 20 52 68 6F</span> 2a 2a  |**<span style='color:#FFBD3F'>Psi Beta Rho</span>**|<br>");
    }
    else if (i == 9) {
        textarea.append("00000090  2a 2a 2a 2a 2a 2a 2a <span style='color:#F44D89'>61  74 20 55 43 4C 41</span> 2a 2a  |*******<span style='color:#F44D89'>at UCLA</span>**|<br>");
    }
    else {
        textarea.append(output[i] + "<br>");
    }
    window.scrollTo(0, document.body.scrollHeight);
    i++;
    time = Math.floor(Math.random() * 4) + 1; // output speed (in ms)
    setTimeout(
        function () {
            if (i < output.length - 2 && document.body.scrollHeight + 70 < window.innerHeight) // stop once screen is filled
                feedbacker();
            else { // clear splash screen and show Home page
                textarea.append("Starting now...<br>");
                setTimeout(function () { $(".load").fadeOut(1000); }, 1000);
            }
        }, time);
}

var output = [
    "00000000  2a 2a 2a 2a 2a 2a 2a 2a  2a 2a 2a 2a 2a 2a 2a 2a  |****************|",
    "00000010  2a 2a 2a 2a 2a 2a 2a 2a  2a 2a 2a 2a 2a 2a 2a 2a  |****************|",
    "00000020  2a 2a 2a 2a 2a 2a 2a 2a  2a 2a 2a 2a 2a 2a 2a 2a  |****************|",
    "00000030  2a 2a 2a 2a 2a 2a 2a 2a  2a 2a 2a 2a 2a 2a 2a 2a  |****************|",
    "00000040  2a 2a 2a 2a 2a 2a 2a 2a  2a 2a 2a 2a 2a 2a 2a 2a  |****************|",
    "00000050  2a 2a 2a 2a 2a 2a 2a 2a  2a 2a 2a 2a 2a 2a 2a 2a  |****************|",
    "00000060  2a 2a 2a 2a 2a 2a 2a 2a  2a 2a 2a 2a 2a 2a 2a 2a  |****************|",
    "00000070  2a 2a 2a 2a 2a 2a 2a 2a  2a 2a 2a 2a 2a 2a 2a 2a  |****************|",
    "00000080  2a 2a 50 73 69 20 42 65  74 61 20 52 68 6F 2a 2a  |**Psi Beta Rho**|",
    "00000090  2a 2a 2a 2a 2a 2a 2a 61  74 20 55 43 4C 41 2a 2a  |*******at UCLA**|",
    "000000A0  2a 2a 2a 2a 2a 2a 2a 2a  2a 2a 2a 2a 2a 2a 2a 2a  |****************|",
    "000000B0  2a 2a 2a 2a 2a 2a 2a 2a  2a 2a 2a 2a 2a 2a 2a 2a  |****************|",
    "000000C0  2a 2a 2a 2a 2a 2a 2a 2a  2a 2a 2a 2a 2a 2a 2a 2a  |****************|",
    "000000D0  2a 2a 2a 2a 2a 2a 2a 2a  2a 2a 2a 2a 2a 2a 2a 2a  |****************|",
    "000000E0  2a 2a 2a 2a 2a 2a 2a 2a  2a 2a 2a 2a 2a 2a 2a 2a  |****************|",
    "000000F0  2a 2a 2a 2a 2a 2a 2a 2a  2a 2a 2a 2a 2a 2a 2a 2a  |****************|",
    "00000100  2a 2a 2a 2a 2a 2a 2a 2a  2a 2a 2a 2a 2a 2a 2a 2a  |****************|",
    "00000110  2a 2a 2a 2a 2a 2a 2a 2a  2a 2a 2a 2a 2a 2a 2a 2a  |****************|",
    "00000120  2a 2a 2a 2a 2a 2a 2a 2a  2a 2a 2a 2a 2a 2a 2a 2a  |****************|",
    "00000130  2a 2a 2a 2a 2a 2a 2a 2a  2a 2a 2a 2a 2a 2a 2a 2a  |****************|",
    "00000140  2a 2a 2a 2a 2a 2a 2a 2a  2a 2a 2a 2a 2a 2a 2a 2a  |****************|",
    "00000150  2a 2a 2a 2a 2a 2a 2a 2a  2a 2a 2a 2a 2a 2a 2a 2a  |****************|",
    "00000160  2a 2a 2a 2a 2a 2a 2a 2a  2a 2a 2a 2a 2a 2a 2a 2a  |****************|",
    "00000170  2a 2a 2a 2a 2a 2a 2a 2a  2a 2a 2a 2a 2a 2a 2a 2a  |****************|",
    "00000180  2a 2a 2a 2a 2a 2a 2a 2a  2a 2a 2a 2a 2a 2a 2a 2a  |****************|",
    "00000190  2a 2a 2a 2a 2a 2a 2a 2a  2a 2a 2a 2a 2a 2a 2a 2a  |****************|",
    "000001A0  2a 2a 2a 2a 2a 2a 2a 2a  2a 2a 2a 2a 2a 2a 2a 2a  |****************|",
    "000001B0  2a 2a 2a 2a 2a 2a 2a 2a  2a 2a 2a 2a 2a 2a 2a 2a  |****************|",
    "000001C0  2a 2a 2a 2a 2a 2a 2a 2a  2a 2a 2a 2a 2a 2a 2a 2a  |****************|",
    "000001D0  2a 2a 2a 2a 2a 2a 2a 2a  2a 2a 2a 2a 2a 2a 2a 2a  |****************|",
    "000001E0  2a 2a 2a 2a 2a 2a 2a 2a  2a 2a 2a 2a 2a 2a 2a 2a  |****************|",
    "000001F0  2a 2a 2a 2a 2a 2a 2a 2a  2a 2a 2a 2a 2a 2a 2a 2a  |****************|",
    "00000200  2a 2a 2a 2a 2a 2a 2a 2a  2a 2a 2a 2a 2a 2a 2a 2a  |****************|",
    "00000210  2a 2a 2a 2a 2a 2a 2a 2a  2a 2a 2a 2a 2a 2a 2a 2a  |****************|",
    "00000220  2a 2a 2a 2a 2a 2a 2a 2a  2a 2a 2a 2a 2a 2a 2a 2a  |****************|",
    "00000230  2a 2a 2a 2a 2a 2a 2a 2a  2a 2a 2a 2a 2a 2a 2a 2a  |****************|",
    "00000240  2a 2a 2a 2a 2a 2a 2a 2a  2a 2a 2a 2a 2a 2a 2a 2a  |****************|",
    "00000250  2a 2a 2a 2a 2a 2a 2a 2a  2a 2a 2a 2a 2a 2a 2a 2a  |****************|",
    "00000260  2a 2a 2a 2a 2a 2a 2a 2a  2a 2a 2a 2a 2a 2a 2a 2a  |****************|",
    "00000270  2a 2a 2a 2a 2a 2a 2a 2a  2a 2a 2a 2a 2a 2a 2a 2a  |****************|",
    "00000280  2a 2a 2a 2a 2a 2a 2a 2a  2a 2a 2a 2a 2a 2a 2a 2a  |****************|",
    "00000290  2a 2a 2a 2a 2a 2a 2a 2a  2a 2a 2a 2a 2a 2a 2a 2a  |****************|",
    "000002A0  2a 2a 2a 2a 2a 2a 2a 2a  2a 2a 2a 2a 2a 2a 2a 2a  |****************|",
    "000002B0  2a 2a 2a 2a 2a 2a 2a 2a  2a 2a 2a 2a 2a 2a 2a 2a  |****************|",
    "000002C0  2a 2a 2a 2a 2a 2a 2a 2a  2a 2a 2a 2a 2a 2a 2a 2a  |****************|",
    "000002D0  2a 2a 2a 2a 2a 2a 2a 2a  2a 2a 2a 2a 2a 2a 2a 2a  |****************|",
    "000002E0  2a 2a 2a 2a 2a 2a 2a 2a  2a 2a 2a 2a 2a 2a 2a 2a  |****************|",
    "000002F0  2a 2a 2a 2a 2a 2a 2a 2a  2a 2a 2a 2a 2a 2a 2a 2a  |****************|",
    "Starting now...", ""];