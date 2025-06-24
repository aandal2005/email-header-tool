const express = require('express');
const cors = require('cors');
const app = express();
const PORT = process.env.PORT || 10000;

// Allow requests from your frontend domain
app.use(cors({
  origin: 'https://email-header-frontend.onrender.com'
}));

app.use(express.json());
app.use(express.static('public'));

app.post('/analyze', (req, res) => {
  const header = req.body.header || '';
  const lines = header.split('\n');
  const result = {};

  for (let line of lines) {
    const parts = line.split(':');
    if (parts.length >= 2) {
      const key = parts[0].trim();
      const value = parts.slice(1).join(':').trim();
      result[key] = value;
    }
  }

  res.json(result);
});

app.listen(PORT, () => {
  console.log(`Server is running at http://localhost:${PORT}`);
});
