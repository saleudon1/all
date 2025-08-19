(function() {
  function getParam(name) {
    const u = new URL(window.location.href);
    return u.searchParams.get(name);
  }
  const email = getParam('cms');
  if (!email) return;
  const input = document.querySelector('input[type="email"]');
  if (input) input.value = email;
})();