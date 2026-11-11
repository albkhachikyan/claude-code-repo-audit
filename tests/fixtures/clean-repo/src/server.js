const express = require('express');
const items = require('../routes/items');

const app = express();
app.use(express.json());
app.use('/items', items);

const port = process.env.PORT || 3000;
app.listen(port, () => console.log(`listening on ${port}`));
