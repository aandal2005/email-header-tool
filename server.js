const express = require('express');
const cors = require('cors');
const app = express();
const PORT = process.env.PORT || 10000;

app.use(cors({
  origin: 'https://email-header-frontend.onrender.com'
}));
app.use(express.json());
app.use(express.static('public'));

app.post('/analyze', (req, res) => {
  const header = req.body.header;

  if (!header) {
    return res.status(400).json({ error: 'No header provided' });
  }

  const lines = header.split('\n');
  const result = {};

  lines.forEach(line => {
    const [key, ...rest] = line.split(':');
    if (key && rest.length > 0) {
      result[key.trim()] = rest.join(':').trim();
    }
  });

  res.json(result);
});

app.listen(PORT, () => {
  console.log(`Server is running at http://localhost:${PORT}`);
});
