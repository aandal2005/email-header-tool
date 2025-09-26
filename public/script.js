// ------------------ CONFIG ------------------
const BACKEND_URL = "https://email-header-backend.onrender.com"; // replace with your deployed backend

// ------------------ LOGIN + REGISTER ------------------
let isSignup = false;

const nameInput = document.getElementById('name');
const emailInput = document.getElementById('email');
const passwordInput = document.getElementById('password');
const formTitle = document.getElementById('formTitle');
const submitBtn = document.getElementById('submitBtn');
const message = document.getElementById('message');
const adminPanelLink = document.getElementById('adminPanelLink');

function toggleForm() {
  isSignup = !isSignup;
  nameInput.style.display = isSignup ? 'block' : 'none';
  formTitle.textContent = isSignup ? 'Sign Up' : 'Login';
  submitBtn.textContent = isSignup ? 'Sign Up' : 'Login';
  document.querySelector('.toggle').textContent =
    isSignup ? 'Already have an account? Login' : "Don't have an account? Sign Up";
  message.textContent = '';
  message.className = '';
}

submitBtn.addEventListener('click', async () => {
  const email = emailInput.value.trim();
  const password = passwordInput.value.trim();
  const name = nameInput.value.trim();

  if (!email || !password || (isSignup && !name)) {
    message.className = 'error';
    message.textContent = '❌ All fields are required';
    return;
  }

  const endpoint = isSignup ? "/register" : "/login";

  try {
    const res = await fetch(`${BACKEND_URL}${endpoint}`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(isSignup ? { name, email, password } : { email, password })
    });

    const data = await res.json();

    if (!res.ok) {
      message.className = 'error';
      message.textContent = `❌ ${data.error || "Something went wrong"}`;
      return;
    }

    message.className = 'success';
    message.textContent = data.message || "✅ Success";

    if (!isSignup && data.token) {
      localStorage.setItem("token", data.token);
      localStorage.setItem("role", data.role);

      if (data.role === "admin") adminPanelLink.style.display = "block";

      setTimeout(() => window.location.href = 'analyzer.html', 1200);
    }
  } catch (err) {
    console.error("❌ Login/Register error:", err);
    message.className = 'error';
    message.textContent = `❌ ${err.message}`;
  }
});

// ------------------ ANALYZE HEADER ------------------
async function analyzeHeader() {
  const header = document.getElementById('headerInput').value;
  if (!header.trim()) {
    document.getElementById('result').innerHTML = '<p style="color:red;">❌ Please paste an email header.</p>';
    return;
  }

  const token = localStorage.getItem('token');
  if (!token) {
    alert('Please login first');
    return;
  }

  try {
    const res = await fetch(`${BACKEND_URL}/analyze`, {
      method: 'POST',
      headers: { 
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${token}`
      },
      body: JSON.stringify({ header })
    });

    if (res.status === 401) throw new Error("Unauthorized – Please login again");
    if (res.status === 404) throw new Error('/analyze endpoint not found');

    const data = await res.json();

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
  } catch (err) {
    console.error('❌ Analyze error:', err);
    document.getElementById('result').innerHTML = `<p style="color:red;">❌ ${err.message}</p>`;
  }
}

// ------------------ FETCH HISTORY ------------------
async function fetchHistory() {
  const token = localStorage.getItem('token');
  if (!token) return;

  try {
    const res = await fetch(`${BACKEND_URL}/history`, {
      headers: { 'Authorization': `Bearer ${token}` }
    });

    if (res.status === 401) throw new Error("Unauthorized – Please login again");
    if (res.status === 404) throw new Error('/history endpoint not found');

    const history = await res.json();
    const historyDiv = document.getElementById('history');
    if (!historyDiv) return;

    historyDiv.style.display = 'block';
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
  } catch (err) {
    console.error('❌ Fetch history error:', err);
    const historyDiv = document.getElementById('history');
    if (historyDiv) historyDiv.innerHTML = `<p style="color:red;">❌ ${err.message}</p>`;
  }
}

// ------------------ ADMIN CLEAR HISTORY ------------------
document.getElementById('clearHistory')?.addEventListener('click', async () => {
  const token = localStorage.getItem('token');
  const role = localStorage.getItem('role');

  if (!token || role !== 'admin') {
    alert('Access denied – Admins only');
    return;
  }

  try {
    const res = await fetch(`${BACKEND_URL}/history`, {
      method: 'DELETE',
      headers: { 'Authorization': `Bearer ${token}` }
    });

    if (res.status === 401) throw new Error("Unauthorized – Please login again");
    if (res.status === 404) throw new Error('/history DELETE endpoint not found');

    const data = await res.json();
    alert(data.message || data.error);
    fetchHistory();
  } catch (err) {
    console.error('❌ Clear history error:', err);
    alert(`❌ ${err.message}`);
  }
});

// ------------------ BUTTON EVENTS ------------------
document.getElementById('analyzeBtn')?.addEventListener('click', analyzeHeader);
document.getElementById('viewBtn')?.addEventListener('click', fetchHistory);
document.getElementById('refreshBtn')?.addEventListener('click', fetchHistory);

// Auto load history if element exists
window.onload = fetchHistory;
