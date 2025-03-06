const config = {
  API_BASE_URL: "https://api1-pp.klokapp.ai/v1",
  MAX_FAILED_ATTEMPTS: 3,
  DELAY_CHAT: [10, 30], //seconds, min: 10s
  REF_CODE: "", //referral code
  AMOUNT_REF: 100, //number of ref to buff
  DELAY_START_BOT: [1, 15],
  DELAY_REQUEST_API: [5, 15],
};
module.exports = { config };
