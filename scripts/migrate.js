const path = require('path');

require('../src/lib/config').load_configuration();

const { create_store, current_schema_version } = require('../src/lib/data-store');

const database_path = process.env.DATABASE_PATH
  ? path.resolve(process.env.DATABASE_PATH)
  : path.join(__dirname, '..', 'database.json');

const store = create_store(database_path);

store.initialize();

console.log(`Database migrated to schema ${current_schema_version}: ${database_path}`);
