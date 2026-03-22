const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const { getDb, closeDb } = require('./db');

async function seed() {
  const db = getDb();

  const password = 'OpsWatch@2024';
  const hash = bcrypt.hashSync(password, 10);

  const users = [
    {
      id: crypto.randomUUID(),
      username: 'admin',
      display_name: 'Admin',
      role: 'admin',
      password_hash: hash,
    },
    {
      id: crypto.randomUUID(),
      username: 'viewer',
      display_name: 'Viewer',
      role: 'viewer',
      password_hash: hash,
    },
  ];

  const insert = db.prepare(
    'INSERT OR IGNORE INTO users (username, password_hash, role) VALUES (?, ?, ?)'
  );

  for (const user of users) {
    insert.run(user.username, user.password_hash, user.role);
    console.log(`Seeded user: ${user.username} (${user.role})`);
  }

  console.log('Seed complete.');
  closeDb();
}

seed().catch((err) => {
  console.error('Seed failed:', err);
  process.exit(1);
});
