// Applies the saved (or OS) colour theme before the first paint, so the page never flashes the wrong
// theme. Same-origin file instead of an inline script: works under a strict Content-Security-Policy.
(function () {
  var root = document.documentElement;
  var dark;
  try {
    var saved = window.localStorage.getItem('securepam.theme');
    dark = saved === 'dark' || (saved !== 'light' && window.matchMedia('(prefers-color-scheme: dark)').matches);
  } catch (e) {
    dark = true;
  }
  root.classList.toggle('dark', dark);
  root.style.colorScheme = dark ? 'dark' : 'light';
})();
