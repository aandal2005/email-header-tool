const BACKEND_URL = 'https://email-header-backend.onrender.com';

// ✅ LOGIN
function login() {
  const email = document.getElementById('username').value; // fixed (use email)
  const password = document.getElementById('password').value;

  fetch(`${BACKEND_URL}/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email, password }) // backend expects email
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
      document.getElementById('loginStatus').innerHTML = '❌ Error during login';
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
    document.getElementById('result').innerHTML = '<p style="color:red;">❌ Please paste an email header.</p>';
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
      fetchHistory(); // refresh history after analyze
    })
    .catch(error => {
      console.error('❌ Analyze error:', error);
      document.getElementById('result').innerHTML = '<p style="color:red;">❌ Failed to analyze header.</p>';
    });
}

// ✅ FETCH HISTORY
function fetchHistory() {
  fetch(`${BACKEND_URL}/history`)
    .then(res => res.json())
    .then(history => {
      const historyDiv = document.getElementById('history');
      historyDiv.style.display = 'block'; // always show history
      historyDiv.innerHTML = '';

      if (!history || history.length === 0) {
        historyDiv.innerHTML = '<p>No history found.</p>';
        return;
      }

      let table = `
        <table border="1" style="border-collapse: collapse; width: 100%; margin-top:10px;">
          <tr>
            <th>From</th><th>To</th><th>Subject</th><th>Date</th>
            <th>SPF</th><th>DKIM</th><th>DMARC</th>
            <th>Safe Meter</th><th>IP</th><th>Location</th>
          </tr>
      `;

      history.forEach(item => {
        table += `
          <tr>
            <td>${item.from || '—'}</td>
            <td>${item.to || '—'}</td>
            <td>${item.subject || '—'}</td>
            <td>${item.date || '—'}</td>
            <td>${item.spf || '—'}</td>
            <td>${item.dkim || '—'}</td>
            <td>${item.dmarc || '—'}</td>
            <td>${item.safeMeter || '—'}</td>
            <td>${item.senderIP || '—'}</td>
            <td>${item.ipLocation || '—'}</td>
          </tr>
        `;
      });

      table += `</table>`;
      historyDiv.innerHTML = table;
    })
    .catch(error => {
      console.error('❌ Fetch history error:', error);
      document.getElementById('history').innerHTML = '<p style="color:red;">❌ Error fetching history.</p>';
    });
}

// ✅ CLEAR HISTORY
function clearHistory() {
  fetch(`${BACKEND_URL}/history`, { method: 'DELETE' })
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

// ✅ VIEW HISTORY (fixed)
function viewHistory() {
  const historyDiv = document.getElementById('history');
  if (historyDiv.style.display === 'none') {
    fetchHistory(); // always load when showing
  } else {
    historyDiv.style.display = 'none'; // toggle hide
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

// Auto load history when page loads
window.onload = fetchHistory;
