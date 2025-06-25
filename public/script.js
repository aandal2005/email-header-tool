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
