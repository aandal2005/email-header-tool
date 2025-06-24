async function analyzeHeader() {
  const headerInput = document.getElementById('headerInput').value;

  const response = await fetch('https://email-header-backend.onrender.com/analyze', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({ header: headerInput }),
  });

  const result = await response.json();

  const resultDiv = document.getElementById('result');
  resultDiv.innerHTML = '<pre>' + JSON.stringify(result, null, 2) + '</pre>';
}
