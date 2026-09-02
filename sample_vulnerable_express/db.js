// tiny stub db
module.exports = { query: (q, p, cb) => (cb || p)(null, []) };
