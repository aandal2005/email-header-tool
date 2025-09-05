const BACKEND_URL = 'https://email-header-backend.onrender.com';

// ✅ LOGIN
function login() {
  const email = document.getElementById('username').value; // frontend input id is "username"
  const password = document.getElementById('password').value;

  fetch(`${BACKEND_URL}/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email, password }) // backend expects "email", not "username"
  })
    .then(res => res.json())
    .then(data => {
      if (data.token) {
        localStorage.setItem('token', data.token);
        localStorage.setItem('role', data.role);
        document.getElementById('loginStatus').innerHTML = `✅ Logged in as ${data.role}`;
        showDashboard(data.role);
      } else {
        document.getElementById('loginStatus').innerHTML = '❌ Login failed';
      }
    })
    .catch(err => {
      console.error('❌ Login error:', err);
      document.getElementById('loginStatus').innerHTML = '❌ Server error';
    });
}

function showDashboard(role) {
  if (role === 'admin') {
    alert('Welcome Admin 👑');
  } else {
    alert('Welcome User 😊');
  }
}

// ✅ ANALYZE HEADER
function analyzeHeader() {
  const header = document.getElementById('headerInput').value;
  if (!header.trim()) {
    document.getElementById('result').innerHTML =
      '<p style="color:red;">❌ Please paste an email header.</p>';
    return;
  }

  fetch(`${BACKEND_URL}/analyze`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ header })
  })
    .then(response => response.json())
    .then(data => {
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
      fetchHistory();
    })
    .catch(error => {
      console.error('❌ Analyze error:', error);
      document.getElementById('result').innerHTML =
        '<p style="color:red;">❌ Failed to analyze header.</p>';
    });
}

// ✅ FETCH HISTORY
function fetchHistory() {
  fetch(`${BACKEND_URL}/history`)
    .then(res => res.json())
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
      console.error('❌ Fetch history error:', error);
      document.getElementById('history').innerHTML =
        '<p style="color:red;">❌ Error fetching history.</p>';
    });
}

// ✅ CLEAR HISTORY
function clearHistory() {
  fetch(`${BACKEND_URL}/history`, {
    method: 'DELETE'
  })
    .then(res => res.json())
    .then(data => {
      alert('✅ ' + data.message);
      document.getElementById('history').innerHTML = '<p>No history found.</p>';
    })
    .catch(error => {
      console.error('❌ Clear history error:', error);
      alert('❌ Failed to clear history');
    });
}

// ✅ VIEW HISTORY
function viewHistory() {
  const historyDiv = document.getElementById('history');
  if (historyDiv.style.display === 'none' || historyDiv.innerHTML === '') {
    fetchHistory();
  } else {
    historyDiv.style.display = 'block';
  }
}

// ✅ REFRESH HISTORY
function refreshHistory() {
  fetchHistory();
}

// ✅ BUTTON EVENTS
document.getElementById('analyzeBtn').addEventListener('click', analyzeHeader);
document.getElementById('viewBtn').addEventListener('click', viewHistory);
document.getElementById('refreshBtn').addEventListener('click', refreshHistory);
document.getElementById('clearBtn').addEventListener('click', clearHistory);

// Auto load history
window.onload = fetchHistory;
