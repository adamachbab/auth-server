function non_negative_integer(value) {
  return Number.isSafeInteger(value) && value >= 0 ? value : 0;
}

module.exports = {
  version: 5,
  description: 'Add reseller accounts, balances, and immutable balance ledger entries.',
  up(db) {
    if (!db.resellers || typeof db.resellers !== 'object' || Array.isArray(db.resellers)) {
      db.resellers = {};
    }

    for (const [discord_id, account] of Object.entries(db.resellers)) {
      if (
        !/^\d{17,20}$/.test(discord_id) ||
        !account ||
        typeof account !== 'object' ||
        Array.isArray(account)
      ) {
        delete db.resellers[discord_id];
        continue;
      }

      account.discord_id = discord_id;
      account.status = account.status === 'disabled' ? 'disabled' : 'active';
      account.balance_cents = non_negative_integer(account.balance_cents);
      account.total_spent_cents = non_negative_integer(account.total_spent_cents);
      account.total_keys_generated = non_negative_integer(account.total_keys_generated);
      account.created_at = Number.isSafeInteger(account.created_at)
        ? account.created_at
        : Math.floor(Date.now() / 1000);
      account.updated_at = Number.isSafeInteger(account.updated_at)
        ? account.updated_at
        : account.created_at;
      account.created_by = typeof account.created_by === 'string' ? account.created_by : null;
    }

    if (!Array.isArray(db.reseller_ledger)) {
      db.reseller_ledger = [];
    }
  }
};
