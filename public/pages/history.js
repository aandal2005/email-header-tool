const BACKEND_URL = 'https://email-header-backend.onrender.com';

// ✅ Fetch History
function fetchHistory() {
  const historyDiv = document.getElementById('history');
  historyDiv.innerHTML = 'Loading history...';

  fetch(`${BACKEND_URL}/history`)
    .then(res => res.json())
    .then(history => {
      historyDiv.innerHTML = '';

      if (!history || history.length === 0) {
        historyDiv.innerHTML = '<p>No history found.</p>';
        return;
      }

      const table = document.createElement('table');
      const headerRow = document.createElement('tr');
      ['From', 'To', 'Subject', 'Date', 'SPF', 'DKIM', 'DMARC', 'Safe Meter', 'IP', 'Location']
        .forEach(text => {
          const th = document.createElement('th');
          th.textContent = text;
          headerRow.appendChild(th);
        });
      table.appendChild(headerRow);

      history.forEach(item => {
        const row = document.createElement('tr');
        [
          item.from, item.to, item.subject, item.date,
          item.spf, item.dkim, item.dmarc,
          item.safeMeter, item.senderIP, item.ipLocation
        ].forEach(text => {
          const td = document.createElement('td');
          td.textContent = text || '—';
          row.appendChild(td);
        });
        table.appendChild(row);
      });

      historyDiv.appendChild(table);
    })
    .catch(err => {
      console.error('❌ Error fetching history:', err);
      historyDiv.innerHTML = '<p style="color:red;">❌ Failed to load history.</p>';
    });
}

// ✅ Clear History
function clearHistory() {
  fetch(`${BACKEND_URL}/history`, { method: 'DELETE' })
    .then(res => res.json())
    .then(data => {
      alert('✅ ' + data.message);
      fetchHistory();
    })
    .catch(err => {
      console.error('❌ Error clearing history:', err);
      alert('❌ Failed to clear history');
    });
}

// Auto load history
window.onload = fetchHistory;
<script src="history.js"></script>
