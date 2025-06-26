function analyzeHeader() {
  const header = document.getElementById('headerInput').value;

  fetch('https://email-header-backend.onrender.com/analyze', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ header })
  })
    .then(response => response.json())
    .then(data => {
      const resultContainer = document.getElementById('result');
      resultContainer.innerHTML = ''; // Clear old result

      if (data.error) {
        resultContainer.innerHTML = `<p style="color:red;">❌ ${data.error}</p>`;
        return;
      }

      const table = document.createElement('table');
      table.style.borderCollapse = 'collapse';
      table.style.width = '100%';

      Object.entries(data).forEach(([key, value]) => {
        const row = document.createElement('tr');

        const keyCell = document.createElement('td');
        keyCell.textContent = key;
        keyCell.style.border = '1px solid #ccc';
        keyCell.style.padding = '8px';
        keyCell.style.fontWeight = 'bold';
        keyCell.style.backgroundColor = '#f0f0f0';

        const valueCell = document.createElement('td');
        valueCell.textContent = value;
        valueCell.style.border = '1px solid #ccc';
        valueCell.style.padding = '8px';

        row.appendChild(keyCell);
        row.appendChild(valueCell);
        table.appendChild(row);
      });

      resultContainer.appendChild(table);
    })
    .catch(error => {
      console.error('Error:', error);
      document.getElementById('result').innerHTML = '<p style="color:red;">❌ Failed to analyze header.</p>';
    });
}
function fetchHistory() {
  fetch('https://email-header-backend.onrender.com/history')
    .then(response => response.json())
    .then(data => {
      const historyContainer = document.getElementById('history');
      historyContainer.innerHTML = '<h3>📜 Recent Analyses</h3>';

      data.forEach(entry => {
        const div = document.createElement('div');
        div.style.border = '1px solid #ccc';
        div.style.padding = '10px';
        div.style.marginBottom = '10px';
        div.style.borderRadius = '8px';
        div.style.backgroundColor = '#f9f9f9';
        div.innerHTML = `
          <strong>From:</strong> ${entry.from}<br>
          <strong>To:</strong> ${entry.to}<br>
          <strong>Subject:</strong> ${entry.subject}<br>
          <strong>Date:</strong> ${entry.date}<br>
          <strong>Safe Meter:</strong> ${entry.safeMeter}<br>
          <strong>IP:</strong> ${entry.senderIP} (${entry.ipLocation})<br>
          <small>Saved: ${new Date(entry.createdAt).toLocaleString()}</small>
        `;
        historyContainer.appendChild(div);
      });
    })
    .catch(err => {
      document.getElementById('history').innerHTML = '❌ Failed to load history';
      console.error(err);
    });
}
