require("dotenv").config();
const { _isArray } = require("../utils/utils.js");

const settings = {
  TIME_SLEEP: process.env.TIME_SLEEP ? parseInt(process.env.TIME_SLEEP) : 8,
  MAX_THEADS: process.env.MAX_THEADS ? parseInt(process.env.MAX_THEADS) : 10,
  MAX_LEVEL_SPEED: process.env.MAX_LEVEL_SPEED ? parseInt(process.env.MAX_LEVEL_SPEED) : 10,
  MAX_THEADS_NO_PROXY: process.env.MAX_THEADS_NO_PROXY ? parseInt(process.env.MAX_THEADS_NO_PROXY) : 10,
  AMOUNT_REF: process.env.AMOUNT_REF ? parseInt(process.env.AMOUNT_REF) : 100,
  NUMBER_PER_REF: process.env.NUMBER_PER_REF ? parseInt(process.env.NUMBER_PER_REF) : 100,
  NUMBER_SEND: process.env.NUMBER_SEND ? parseInt(process.env.NUMBER_SEND) : 10,
  NUMBER_SWAP: process.env.NUMBER_SWAP ? parseInt(process.env.NUMBER_SWAP) : 10,
  NUMBER_ADDLP: process.env.NUMBER_ADDLP ? parseInt(process.env.NUMBER_ADDLP) : 10,
  AMOUNT_CHAT: process.env.AMOUNT_CHAT ? parseInt(process.env.AMOUNT_CHAT) : 10,

  SKIP_TASKS: process.env.SKIP_TASKS ? JSON.parse(process.env.SKIP_TASKS.replace(/'/g, '"')) : [],
  TYPE_HERO_UPGRADE: process.env.TYPE_HERO_UPGRADE ? JSON.parse(process.env.TYPE_HERO_UPGRADE.replace(/'/g, '"')) : [],
  TYPE_HERO_RESET: process.env.TYPE_HERO_RESET ? JSON.parse(process.env.TYPE_HERO_RESET.replace(/'/g, '"')) : [],
  TOKENS_FAUCET: process.env.TOKENS_FAUCET ? JSON.parse(process.env.TOKENS_FAUCET.replace(/'/g, '"')) : [],
  TASKS_ID: process.env.TASKS_ID ? JSON.parse(process.env.TASKS_ID.replace(/'/g, '"')) : [],
  AGENTS: process.env.AGENTS ? JSON.parse(process.env.AGENTS.replace(/'/g, '"')) : [],

  AUTO_TASK: process.env.AUTO_TASK ? process.env.AUTO_TASK.toLowerCase() === "true" : false,
  AUTO_CHAT: process.env.AUTO_CHAT ? process.env.AUTO_CHAT.toLowerCase() === "true" : false,
  ENABLE_MAP_RANGE_CHALLENGE: process.env.ENABLE_MAP_RANGE_CHALLENGE ? process.env.ENABLE_MAP_RANGE_CHALLENGE.toLowerCase() === "true" : false,

  AUTO_SHOW_COUNT_DOWN_TIME_SLEEP: process.env.AUTO_SHOW_COUNT_DOWN_TIME_SLEEP ? process.env.AUTO_SHOW_COUNT_DOWN_TIME_SLEEP.toLowerCase() === "true" : false,
  AUTO_CLAIM_BONUS: process.env.AUTO_CLAIM_BONUS ? process.env.AUTO_CLAIM_BONUS.toLowerCase() === "true" : false,
  ENABLE_ADVANCED_MERGE: process.env.ENABLE_ADVANCED_MERGE ? process.env.ENABLE_ADVANCED_MERGE.toLowerCase() === "true" : false,
  ENABLE_DEBUG: process.env.ENABLE_DEBUG ? process.env.ENABLE_DEBUG.toLowerCase() === "true" : false,

  AUTO_STAKE: process.env.AUTO_STAKE ? process.env.AUTO_STAKE.toLowerCase() === "true" : false,
  AUTO_BUY_PET: process.env.AUTO_BUY_PET ? process.env.AUTO_BUY_PET.toLowerCase() === "true" : false,
  AUTO_FAUCET_STABLE_COIN: process.env.AUTO_FAUCET_STABLE_COIN ? process.env.AUTO_FAUCET_STABLE_COIN.toLowerCase() === "true" : false,

  AUTO_ADDLP: process.env.AUTO_ADDLP ? process.env.AUTO_ADDLP.toLowerCase() === "true" : false,

  ADVANCED_ANTI_DETECTION: process.env.ADVANCED_ANTI_DETECTION ? process.env.ADVANCED_ANTI_DETECTION.toLowerCase() === "true" : false,
  AUTO_TAP: process.env.AUTO_TAP ? process.env.AUTO_TAP.toLowerCase() === "true" : false,
  USE_PROXY: process.env.USE_PROXY ? process.env.USE_PROXY.toLowerCase() === "true" : false,
  AUTO_DAILY_COMBO: process.env.AUTO_DAILY_COMBO ? process.env.AUTO_DAILY_COMBO.toLowerCase() === "true" : false,
  AUTO_FAUCET: process.env.AUTO_FAUCET ? process.env.AUTO_FAUCET.toLowerCase() === "true" : false,
  AUTO_SWAP: process.env.AUTO_SWAP ? process.env.AUTO_SWAP.toLowerCase() === "true" : false,
  AUTO_SEND: process.env.AUTO_SEND ? process.env.AUTO_SEND.toLowerCase() === "true" : false,

  API_ID: process.env.API_ID ? process.env.API_ID : null,
  BASE_URL: process.env.BASE_URL ? process.env.BASE_URL : null,
  BASE_URL_V2: process.env.BASE_URL_V2 ? process.env.BASE_URL_V2 : "https://testnet-router.zenithswap.xyz",
  REF_CODE: process.env.REF_CODE ? process.env.REF_CODE : "IXWO7UTF",
  RPC_URL: process.env.RPC_URL ? process.env.RPC_URL : "https://evmrpc-testnet.0g.ai",
  CHAIN_ID: process.env.CHAIN_ID ? process.env.CHAIN_ID : 688688,

  TYPE_CAPTCHA: process.env.TYPE_CAPTCHA ? process.env.TYPE_CAPTCHA : null,
  API_KEY_2CAPTCHA: process.env.API_KEY_2CAPTCHA ? process.env.API_KEY_2CAPTCHA : null,
  API_KEY_ANTI_CAPTCHA: process.env.API_KEY_ANTI_CAPTCHA ? process.env.API_KEY_ANTI_CAPTCHA : null,
  CAPTCHA_URL: process.env.CAPTCHA_URL ? process.env.CAPTCHA_URL : null,
  WEBSITE_KEY: process.env.WEBSITE_KEY ? process.env.WEBSITE_KEY : null,
  SELOCK_ID: process.env.SELOCK_ID ? process.env.SELOCK_ID : null,
  CRYPTO_BUDDY_ID: process.env.CRYPTO_BUDDY_ID ? process.env.CRYPTO_BUDDY_ID : null,
  PROFESSOR_ID: process.env.PROFESSOR_ID ? process.env.PROFESSOR_ID : null,

  DELAY_BETWEEN_REQUESTS: process.env.DELAY_BETWEEN_REQUESTS && _isArray(process.env.DELAY_BETWEEN_REQUESTS) ? JSON.parse(process.env.DELAY_BETWEEN_REQUESTS) : [1, 5],
  DELAY_START_BOT: process.env.DELAY_START_BOT && _isArray(process.env.DELAY_START_BOT) ? JSON.parse(process.env.DELAY_START_BOT) : [1, 15],
  AMOUNT_STAKE: process.env.AMOUNT_STAKE && _isArray(process.env.AMOUNT_STAKE) ? JSON.parse(process.env.AMOUNT_STAKE) : [1, 15],
  AMOUNT_TAPS: process.env.AMOUNT_TAPS && _isArray(process.env.AMOUNT_TAPS) ? JSON.parse(process.env.AMOUNT_TAPS) : [10, 15],
  DELAY_TASK: process.env.DELAY_TASK && _isArray(process.env.DELAY_TASK) ? JSON.parse(process.env.DELAY_TASK) : [10, 15],
  AMOUNT_SEND: process.env.AMOUNT_SEND && _isArray(process.env.AMOUNT_SEND) ? JSON.parse(process.env.AMOUNT_SEND) : [0.1, 0.2],
  AMOUNT_SWAP: process.env.AMOUNT_SWAP && _isArray(process.env.AMOUNT_SWAP) ? JSON.parse(process.env.AMOUNT_SWAP) : [0.1, 0.2],
  DELAY_CHAT: process.env.DELAY_CHAT && _isArray(process.env.DELAY_CHAT) ? JSON.parse(process.env.DELAY_CHAT) : [5, 30],
};

module.exports = settings;
