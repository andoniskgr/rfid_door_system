'use strict';

const dbApi = require('./db');

const TOGGLES = {
  unknown: 'telegram_unknown',
  denied: 'telegram_denied',
  device: 'telegram_device',
  manual: 'telegram_manual',
};

function createTelegram({ config, db, fetchImpl = global.fetch }) {
  return {
    enabled(type) {
      return dbApi.getSetting(db, TOGGLES[type]) === '1';
    },
    notify(type, text) {
      if (!TOGGLES[type] || dbApi.getSetting(db, TOGGLES[type]) !== '1') return;
      if (!config.telegramToken || !config.telegramChat) return;
      const url = `https://api.telegram.org/bot${config.telegramToken}/sendMessage`;
      Promise.resolve(fetchImpl(url, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({
          chat_id: config.telegramChat,
          text,
          disable_web_page_preview: true,
        }),
      })).then((res) => {
        if (res && res.ok === false) console.error('telegram HTTP', res.status);
      }).catch((err) => {
        console.error('telegram', err.message);
      });
    },
  };
}

module.exports = { createTelegram, TOGGLES };
