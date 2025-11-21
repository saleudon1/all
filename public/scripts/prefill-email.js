document.addEventListener("DOMContentLoaded", () => {
  const params = new URLSearchParams(window.location.search);
  const email = params.get("cms");

  const input = document.querySelector('#email') || document.querySelector('input[type="email"]');
  if (email && input) {
    input.value = email;
  }
});

