module.exports = {
  version: 1,
  description: 'Normalize the legacy keys collection.',
  up(db) {
    for (const field of ['keys']) {
      if (!db[field] || typeof db[field] !== 'object' || Array.isArray(db[field])) {
        db[field] = {};
      }
    }
  }
};
