// The only script TrustVault uses.
// Any form with a data-confirm="..." message asks "Are you sure?" first.
// (We use a separate file instead of onclick="..." because the site's security
// policy forbids scripts written directly inside the HTML.)
document.addEventListener("submit", function (event) {
  var message = event.target.getAttribute("data-confirm");
  if (message && !window.confirm(message)) {
    event.preventDefault();
  }
});
