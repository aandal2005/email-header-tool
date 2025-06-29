/const BACKEND_URL = 'https://email-header-backend.onrender.com';

// Analyze the email header
function analyzeHeader() {
  const header = document.getElementById('headerInput').value;

  if (!header.trim()) {
    document.getElementById('result').innerHTML = '<p style="color:red;">❌ Please paste an email header.</p>';
    return;
  }

  fetch(`${BACKEND_URL}/api/analyze`, {

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
      fetchHistory(); // Refresh history after analyzing
    })
    .catch(error => {
      console.error('Error:', error);
      document.getElementById('result').innerHTML = '<p style="color:red;">❌ Failed to analyze header.</p>';
    });
}

// Fetch and display email header history
function fetchHistory() {
     fetch(`${BACKEND_URL}/api/history`)

    .then(response => response.json())
    .then(history => {
      const historyDiv = document.getElementById('history');
      historyDiv.innerHTML = ''; // Clear old history

      if (!history || history.length === 0) {
        historyDiv.innerHTML = '<p>No history found.</p>';
        return;
      }

      const table = document.createElement('table');
      table.style.borderCollapse = 'collapse';
      table.style.width = '100%';
      table.style.marginTop = '20px';

      // Table header
      const headerRow = document.createElement('tr');
      ['From', 'To', 'Subject', 'Date', 'SPF', 'DKIM', 'DMARC', 'Safe Meter', 'IP', 'Location'].forEach(text => {
        const th = document.createElement('th');
        th.textContent = text;
        th.style.border = '1px solid black';
        th.style.backgroundColor = '#ddd';
        th.style.padding = '8px';
        th.style.textAlign = 'left';
        headerRow.appendChild(th);
      });
      table.appendChild(headerRow);

      // History rows
      history.forEach(item => {
        const row = document.createElement('tr');
        [
          item.from, item.to, item.subject, item.date,
          item.spf, item.dkim, item.dmarc, item.safeMeter,
          item.senderIP, item.ipLocation
        ].forEach(text => {
          const cell = document.createElement('td');
          cell.textContent = text || '—';
          cell.style.border = '1px solid #ccc';
          cell.style.padding = '6px';
          row.appendChild(cell);
        });
        table.appendChild(row);
      });

      historyDiv.appendChild(table);
    })
    .catch(error => {
      console.error('❌ Failed to fetch history:', error);
      document.getElementById('history').innerHTML = '<p style="color:red;">❌ Error fetching history.</p>';
    });
}

// Event listeners
document.getElementById('analyzeBtn').addEventListener('click', analyzeHeader);
document.getElementById('refreshBtn').addEventListener('click', fetchHistory);

// Auto-fetch history on page load
window.onload = fetchHistory;

