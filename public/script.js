const BACKEND_URL = 'https://email-header-backend.onrender.com';

// Analyze the email header and show result in a table
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
      if (data.error) {
        document.getElementById('result').innerHTML = `<p style="color:red;">❌ ${data.error}</p>`;
        return;
      }

      const resultDiv = document.getElementById('result');
      resultDiv.innerHTML = `
        <table border="1" style="border-collapse: collapse; margin-top: 10px; width: 100%;">
          <tr><th>From</th><td>${data.from}</td></tr>
          <tr><th>To</th><td>${data.to}</td></tr>
          <tr><th>Subject</th><td>${data.subject}</td></tr>
          <tr><th>Date</th><td>${data.date}</td></tr>
          <tr><th>SPF</th><td>${data.spf}</td></tr>
          <tr><th>DKIM</th><td>${data.dkim}</td></tr>
          <tr><th>DMARC</th><td>${data.dmarc}</td></tr>
          <tr><th>Safe Meter</th><td>${data.safeMeter}</td></tr>
          <tr><th>IP</th><td>${data.senderIP}</td></tr>
          <tr><th>Location</th><td>${data.ipLocation}</td></tr>
        </table>
      `;

      fetchHistory(); // Update history after analysis
    })
    .catch(error => {
      console.error('❌ Analyze error:', error);
      document.getElementById('result').innerHTML = '<p style="color:red;">❌ Failed to analyze header.</p>';
    });
}

// Fetch history from backend and display
function fetchHistory() {
  fetch(`${BACKEND_URL}/api/history`)
    .then(response => response.json())
    .then(history => {
      const historyDiv = document.getElementById('history');
      historyDiv.style.display = 'block';
      historyDiv.innerHTML = '';

      if (!history || history.length === 0) {
        historyDiv.innerHTML = '<p class="no-history">No history found.</p>';
        return;
      }

      const table = document.createElement('table');
      table.innerHTML = `
        <tr>
          <th>From</th><th>To</th><th>Subject</th><th>Date</th>
          <th>SPF</th><th>DKIM</th><th>DMARC</th><th>Safe Meter</th>
          <th>IP</th><th>Location</th>
        </tr>
      `;

      history.forEach(item => {
        const row = document.createElement('tr');
        [
          item.from, item.to, item.subject, item.date,
          item.spf, item.dkim, item.dmarc, item.safeMeter,
          item.senderIP, item.ipLocation
        ].forEach(text => {
          const cell = document.createElement('td');
          cell.textContent = text || '—';
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

// View history (if hidden)
function viewHistory() {
  const historyDiv = document.getElementById('history');
  if (historyDiv.style.display === 'none' || historyDiv.innerHTML === '') {
    fetchHistory();
  } else {
    historyDiv.style.display = 'block';
  }
}

// Always re-fetch history
function refreshHistory() {
  fetchHistory();
}

// Clear history from backend and update UI
function clearHistory() {
  fetch(`${BACKEND_URL}/api/history`, {
    method: 'DELETE'
  })
    .then(response => response.json())
    .then(data => {
      alert('✅ ' + data.message);
      document.getElementById('history').innerHTML = '<p class="no-history">No history found.</p>';
    })
    .catch(error => {
      console.error('❌ Clear history error:', error);
      alert('❌ Failed to clear history');
    });
}

// Attach button click handlers
document.getElementById('analyzeBtn').addEventListener('click', analyzeHeader);
document.getElementById('viewBtn').addEventListener('click', viewHistory);
document.getElementById('refreshBtn').addEventListener('click', refreshHistory);
document.getElementById('clearBtn').addEventListener('click', clearHistory);

// Auto-fetch history on page load
window.onload = fetchHistory;
