// gen_hash.js
const bcrypt = require('bcrypt');

(async () => {
  const hash = await bcrypt.hash('Seeds@123', 10);
  console.log(hash);
})();