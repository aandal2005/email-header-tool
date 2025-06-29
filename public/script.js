const BACKEND_URL = 'https://email-header-backend.onrender.com';

// Analyze header function
function analyzeHeader() {
  const header = document.getElementById('headerInput').value.trim();
  if (!header) return alert('Please paste an email header.');

  fetch(`${BACKEND_URL}/api/analyze`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ header })
  })
    .then(res => res.json())
    .then(data => {
      document.getElementById('result').textContent = JSON.stringify(data, null, 2);
    })
    .catch(err => {
      console.error('❌ Analyze error:', err);
      document.getElementById('result').textContent = '❌ Failed to analyze header.';
    });
}

// Fetch history from backend
function fetchHistory() {
  fetch(`${BACKEND_URL}/api/history`)
    .then(response => response.json())
    .then(history => {
      const historyDiv = document.getElementById('history');
      historyDiv.style.display = 'block';
      historyDiv.innerHTML = '';

      if (!history || history.length === 0) {
        historyDiv.innerHTML = '<p>No history found.</p>';
        return;
      }

      const table = document.createElement('table');
      table.style.borderCollapse = 'collapse';
      table.style.width = '100%';

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

// Toggle history display
function viewHistory() {
  const historyDiv = document.getElementById('history');
  if (historyDiv.style.display === 'none' || historyDiv.innerHTML === '') {
    fetchHistory();
  } else {
    historyDiv.style.display = 'none';
  }
}

// Refresh history forcibly
function refreshHistory() {
  fetchHistory();
}

// Bind buttons
document.getElementById('viewBtn').addEventListener('click', viewHistory);
document.getElementById('refreshBtn').addEventListener('click', refreshHistory);
