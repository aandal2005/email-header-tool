const BACKEND_URL = 'https://email-header-backend.onrender.com';

// ✅ Fetch History
function fetchHistory() {
  const historyTable = document.getElementById('historyTable');
  historyTable.innerHTML = '<tr><td colspan="11">Loading history...</td></tr>';

  const token = localStorage.getItem('token'); // ✅ Get token
  if (!token) {
    historyTable.innerHTML = '<tr><td colspan="11" style="color:red;">You must log in first!</td></tr>';
    return;
  }

  fetch(`${BACKEND_URL}/history`, {
    headers: { 'Authorization': 'Bearer ' + token }
  })
    .then(res => res.json())
    .then(history => {
      if (!history || history.length === 0) {
        historyTable.innerHTML = '<tr><td colspan="11">No history found.</td></tr>';
        return;
      }

      historyTable.innerHTML = '';
      history.forEach((item, index) => {
        const tr = document.createElement('tr');
        tr.innerHTML = `
          <td>${index + 1}</td>
          <td>${item.from || '—'}</td>
          <td>${item.to || '—'}</td>
          <td>${item.subject || '—'}</td>
          <td>${new Date(item.createdAt).toLocaleString()}</td>
          <td>${item.spf || '—'}</td>
          <td>${item.dkim || '—'}</td>
          <td>${item.dmarc || '—'}</td>
          <td>${item.safeMeter || '—'}</td>
          <td>${item.senderIP || '—'}</td>
          <td>${item.ipLocation || '—'}</td>
        `;
        historyTable.appendChild(tr);
      });
    })
    .catch(err => {
      console.error('❌ Error fetching history:', err);
      historyTable.innerHTML = '<tr><td colspan="11" style="color:red;">Failed to load history.</td></tr>';
    });
}

async function deleteHistory(id) {
  const token = localStorage.getItem("token");
  if (!token) {
    alert("You must log in first!");
    return;
  }

  if (!confirm("Are you sure you want to delete this record?")) return;

  try {
    const res = await fetch(`https://email-header-backend.onrender.com/history/${id}`, {
      method: "DELETE",
      headers: { "Authorization": "Bearer " + token }
    });

    if (!res.ok) throw new Error("Failed to delete");

    alert("Deleted successfully");
    window.location.reload(); // refresh table
  } catch (err) {
    alert("Error deleting: " + err.message);
  }
}

// ✅ Clear History (Admins only)
function clearHistory() {
  const token = localStorage.getItem('token');
  if (!token) {
    alert('❌ You must log in first!');
    return;
  }

  fetch(`${BACKEND_URL}/history`, {
    method: 'DELETE',
    headers: { 'Authorization': 'Bearer ' + token }
  })
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

// Auto load history on page load
window.onload = fetchHistory;
