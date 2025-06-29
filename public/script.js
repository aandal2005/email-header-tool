const BACKEND_URL = 'https://email-header-backend.onrender.com';

// Analyze email header
function analyzeHeader() {
  const input = document.getElementById('headerInput').value.trim();
  const resultDiv = document.getElementById('result');
  resultDiv.innerHTML = '';
  if (!input) {
    resultDiv.innerHTML = '<p style="color:red;">❌ Please paste an email header.</p>';
    return;
  }

  fetch(`${BACKEND_URL}/api/analyze`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({ header: input })
  })
    .then(response => response.json())
    .then(data => {
      if (data.error) {
        resultDiv.innerHTML = `<p style="color:red;">❌ ${data.error}</p>`;
      } else {
        resultDiv.innerHTML = `
          <h4>Result:</h4>
          <pre>${JSON.stringify(data, null, 2)}</pre>
        `;
        fetchHistory(); // Auto-refresh history after analysis
      }
    })
    .catch(error => {
      console.error('❌ Analyze error:', error);
      resultDiv.innerHTML = '<p style="color:red;">❌ Failed to analyze header.</p>';
    });
}

// Fetch history from backend and display
function fetchHistory() {
  fetch(`${BACKEND_URL}/api/history`)
    .then(response => response.json())
    .then(history => {
      const historyDiv = document.getElementById('history');
      historyDiv.style.display = 'block'; // Ensure it's visible
      historyDiv.innerHTML = ''; // Clear old history

      if (!history || history.length === 0) {
        historyDiv.innerHTML = '<p>No history found.</p>';
        return;
      }

      const table = document.createElement('table');
      table.style.borderCollapse = 'collapse';
      table.style.width = '100%';
      table.style.marginTop = '20px';

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

      history.forEach(item => {
        const row = document.createElement('tr');
        [item.from, item.to, item.subject, item.date, item.spf, item.dkim, item.dmarc, item.safeMeter, item.senderIP, item.ipLocation].forEach(text => {
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
      console.error('❌ Error fetching history:', error);
      document.getElementById('history').innerHTML = '<p style="color:red;">❌ Error fetching history.</p>';
    });
}

// ✅ View History - only show if hidden or empty
function viewHistory() {
  const historyDiv = document.getElementById('history');
  if (historyDiv.style.display === 'none' || historyDiv.innerHTML === '') {
    fetchHistory(); // Only fetch if hidden or empty
  } else {
    historyDiv.style.display = 'block'; // Just ensure it's shown
  }
}

// ✅ Refresh History - always re-fetch
function refreshHistory() {
  fetchHistory();
}

// 🔘 Attach button events
document.getElementById('analyzeBtn').addEventListener('click', analyzeHeader);
document.getElementById('viewBtn').addEventListener('click', viewHistory);
document.getElementById('refreshBtn').addEventListener('click', refreshHistory);
