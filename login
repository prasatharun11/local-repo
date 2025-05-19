signIn.renderEl(
  { el: '#okta-login-container' },
  function success(res) {
    console.log("Login success", res);
  },
  function error(err) {
    console.error("Login error", err);
  }
);

// MutationObserver to track form changes
const observer = new MutationObserver(() => {
  const usernameInput = document.querySelector('input[name="username"]');
  const passwordInput = document.querySelector('input[name="password"]');
  const nextBtn = document.querySelector('input[type="submit"]');

  if (nextBtn && usernameInput && !nextBtn._usernameHandled) {
    nextBtn._usernameHandled = true;
    nextBtn.addEventListener('click', () => {
      console.log("Username step submitted:", usernameInput.value);
    });
  }

  if (nextBtn && passwordInput && !nextBtn._passwordHandled) {
    nextBtn._passwordHandled = true;
    nextBtn.addEventListener('click', () => {
      console.log("Password step submitted (not logging password)");
    });
  }
});

observer.observe(document.getElementById('okta-login-container'), {
  childList: true,
  subtree: true,
});