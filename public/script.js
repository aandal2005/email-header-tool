async function analyzeHeader() {
  const header = document.getElementById("headerInput").value;

  const response = await fetch("https://email-header-backend.onrender.com/analyze", {
    method: "POST",
    headers: {
      "Content-Type": "application/json"
    },
    body: JSON.stringify({ header })
  });

  const data = await response.json();
  document.getElementById("result").textContent = JSON.stringify(data, null, 2);
}
