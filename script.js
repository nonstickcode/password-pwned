// Autofocus on the password input field upon page load
document.addEventListener('DOMContentLoaded', function() {
  document.getElementById('passwordInput').focus();
});

// Event listener for the password input to submit on Enter key press
document.getElementById('passwordInput').addEventListener('keypress', function(event) {
  if (event.key === 'Enter') {
      event.preventDefault(); // Prevent default form submission
      document.getElementById('checkButton').click(); // Trigger password check
  }
});

// Password check functionality on click
document.getElementById('checkButton').addEventListener('click', function() {
  const password = document.getElementById('passwordInput').value;
  const hashedPassword = sha1(password);
  const prefix = hashedPassword.substring(0, 5);
  const suffix = hashedPassword.substring(5).toUpperCase();

  fetch(`https://api.pwnedpasswords.com/range/${prefix}`)
      .then(response => response.text())
      .then(text => {
          const lines = text.split('\n');
          const pwned = lines.some(line => line.split(':')[0] === suffix);
          const resultElement = document.getElementById('result');
          
          if (pwned) {
              resultElement.textContent = "has been compromised.";
              resultElement.style.color = 'red';
          } else {
              resultElement.textContent = "appears to be safe.";
              resultElement.style.color = 'green';
          }
      })
      .catch(error => {
          console.error('Error:', error);
          const resultElement = document.getElementById('result');
          resultElement.textContent = "There was an error checking your password.";
          resultElement.style.color = 'black'; // Default color for errors
      });
});


// SHA-1 Hashing Function
function sha1(msg) {
  function rotl(n, s) { return n << s | n >>> 32 - s; };
  function tohex(i) { for (var h = "", s = 28; ; s -= 4) { h += (i >>> s & 0xf).toString(16); if (!s) return h; } };

  var h0 = 0x67452301, h1 = 0xEFCDAB89, h2 = 0x98BADCFE, h3 = 0x10325476, h4 = 0xC3D2E1F0,
      b, c, d, e, f, k, l, t, W = new Array(80), ml = msg.length, wa = [];
  msg += String.fromCharCode(0x80);
  while (msg.length % 64 != 56) msg += String.fromCharCode(0x00);
  for (var i = 0; i < msg.length; i += 4) {
      wa.push(msg.charCodeAt(i) << 24 | msg.charCodeAt(i + 1) << 16 |
          msg.charCodeAt(i + 2) << 8 | msg.charCodeAt(i + 3));
  }
  wa.push(ml >>> 29), wa.push((ml << 3) & 0x0ffffffff);
  for (var x = 0; x < wa.length; x += 16) {
      for (i = 0; i < 16; i++) W[i] = wa[x + i];
      for (i = 16; i <= 79; i++) W[i] = rotl(W[i - 3] ^ W[i - 8] ^ W[i - 14] ^ W[i - 16], 1);
      a = h0, b = h1, c = h2, d = h3, e = h4;
      for (i = 0; i <= 19; i++) {
          f = (b & c) | ((~b) & d), k = 0x5A827999, t = rotl(a, 5) + f + e + k + W[i], e = d, d = c, c = rotl(b, 30), b = a, a = t;
      }
      for (i = 20; i <= 39; i++) {
          f = b ^ c ^ d, k = 0x6ED9EBA1, t = rotl(a, 5) + f + e + k + W[i], e = d, d = c, c = rotl(b, 30), b = a, a = t;
      }
      for (i = 40; i <= 59; i++) {
          f = (b & c) | (b & d) | (c & d), k = 0x8F1BBCDC, t = rotl(a, 5) + f + e + k + W[i], e = d, d = c, c = rotl(b, 30), b = a, a = t;
      }
      for (i = 60; i <= 79; i++) {
          f = b ^ c ^ d, k = 0xCA62C1D6, t = rotl(a, 5) + f + e + k + W[i], e = d, d = c, c = rotl(b, 30), b = a, a = t;
      }
      h0 = h0 + a | 0, h1 = h1 + b | 0, h2 = h2 + c | 0, h3 = h3 + d | 0, h4 = h4 + e | 0;
  }
  return tohex(h0) + tohex(h1) + tohex(h2) + tohex(h3) + tohex(h4);
}


// Modal interaction logic
var modal = document.getElementById('infoModal');
var btn = document.getElementById('infoButton');
var span = document.getElementsByClassName('close')[0];

btn.onclick = function() {
    modal.style.display = "block";
}

span.onclick = function() {
    modal.style.display = "none";
}

window.onclick = function(event) {
    if (event.target == modal) {
        modal.style.display = "none";
    }
}