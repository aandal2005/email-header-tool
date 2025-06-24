async function analyzeHeader() {
  const headerText = document.getElementById('headerInput').value;

  const response = await fetch("https://email-header-backend.onrender.com/analyze", {
    method: "POST",
    headers: {
      "Content-Type": "application/json"
    },
    body: JSON.stringify({ header: headerText })
  });

  const result = await response.json();
  document.getElementById("result").innerText = JSON.stringify(result, null, 2);
}
