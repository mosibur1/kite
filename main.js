const fs = require("fs");
const path = require("path");
const axios = require("axios");
const colors = require("colors");
const { HttpsProxyAgent } = require("https-proxy-agent");
const readline = require("readline");
const user_agents = require("./config/userAgents");
const settings = require("./config/config.js");
const { sleep, loadData, getRandomNumber, saveToken, isTokenExpired, saveJson, getRandomElement } = require("./utils/utils.js");
const { Worker, isMainThread, parentPort, workerData } = require("worker_threads");
const { checkBaseUrl } = require("./utils/checkAPI.js");
const { headers } = require("./core/header.js");
const { showBanner } = require("./core/banner.js");
const localStorage = require("./localStorage.json");
const ethers = require("ethers");
const { solveCaptcha } = require("./utils/captcha.js");
const ProfessorQuestions = loadData("./questions/Professor.txt");
const Crypto_BuddyQuestions = loadData("./questions/Crypto_Buddy.txt");
const SherlockQuestions = loadData("./questions/Sherlock.txt");

const emails = [];
const twitters = [];
const crypto = require("crypto");
// const refcodes = loadData("reffCodes.txt");
let REF_CODE = settings.REF_CODE;
class ClientAPI {
  constructor(itemData, accountIndex, proxy, baseURL) {
    this.headers = headers;
    this.baseURL = settings.BASE_URL;
    this.baseURL_v2 = settings.BASE_URL_V2;
    this.localItem = null;
    this.itemData = itemData;
    this.accountIndex = accountIndex;
    this.proxy = proxy;
    this.proxyIP = null;
    this.session_name = null;
    this.session_user_agents = this.#load_session_data();
    this.token = null;
    this.localStorage = localStorage;
    this.wallet = new ethers.Wallet(this.itemData.privateKey);
    this.apiKey = "c99bed7f3bad473eb888213b29ae3744";
  }

  #load_session_data() {
    try {
      const filePath = path.join(process.cwd(), "session_user_agents.json");
      const data = fs.readFileSync(filePath, "utf8");
      return JSON.parse(data);
    } catch (error) {
      if (error.code === "ENOENT") {
        return {};
      } else {
        throw error;
      }
    }
  }

  #get_random_user_agent() {
    const randomIndex = Math.floor(Math.random() * user_agents.length);
    return user_agents[randomIndex];
  }

  #get_user_agent() {
    if (this.session_user_agents[this.session_name]) {
      return this.session_user_agents[this.session_name];
    }

    console.log(`[Tài khoản ${this.accountIndex + 1}] Tạo user agent...`.blue);
    const newUserAgent = this.#get_random_user_agent();
    this.session_user_agents[this.session_name] = newUserAgent;
    this.#save_session_data(this.session_user_agents);
    return newUserAgent;
  }

  #save_session_data(session_user_agents) {
    const filePath = path.join(process.cwd(), "session_user_agents.json");
    fs.writeFileSync(filePath, JSON.stringify(session_user_agents, null, 2));
  }

  #get_platform(userAgent) {
    const platformPatterns = [
      { pattern: /iPhone/i, platform: "ios" },
      { pattern: /Android/i, platform: "android" },
      { pattern: /iPad/i, platform: "ios" },
    ];

    for (const { pattern, platform } of platformPatterns) {
      if (pattern.test(userAgent)) {
        return platform;
      }
    }

    return "Unknown";
  }

  #set_headers() {
    const platform = this.#get_platform(this.#get_user_agent());
    this.headers["sec-ch-ua"] = `Not)A;Brand";v="99", "${platform} WebView";v="127", "Chromium";v="127`;
    this.headers["sec-ch-ua-platform"] = platform;
    this.headers["User-Agent"] = this.#get_user_agent();
  }

  createUserAgent() {
    try {
      this.session_name = this.itemData.address;
      this.#get_user_agent();
    } catch (error) {
      this.log(`Can't create user agent: ${error.message}`, "error");
      return;
    }
  }

  async log(msg, type = "info") {
    const accountPrefix = `[KITE][${this.accountIndex + 1}][${this.itemData.address}]`;
    let ipPrefix = "[Local IP]";
    if (settings.USE_PROXY) {
      ipPrefix = this.proxyIP ? `[${this.proxyIP}]` : "[Unknown IP]";
    }
    let logMessage = "";

    switch (type) {
      case "success":
        logMessage = `${accountPrefix}${ipPrefix} ${msg}`.green;
        break;
      case "error":
        logMessage = `${accountPrefix}${ipPrefix} ${msg}`.red;
        break;
      case "warning":
        logMessage = `${accountPrefix}${ipPrefix} ${msg}`.yellow;
        break;
      case "custom":
        logMessage = `${accountPrefix}${ipPrefix} ${msg}`.magenta;
        break;
      default:
        logMessage = `${accountPrefix}${ipPrefix} ${msg}`.blue;
    }
    console.log(logMessage);
  }

  async checkProxyIP() {
    try {
      const proxyAgent = new HttpsProxyAgent(this.proxy);
      const response = await axios.get("https://api.ipify.org?format=json", { httpsAgent: proxyAgent });
      if (response.status === 200) {
        this.proxyIP = response.data.ip;
        return response.data.ip;
      } else {
        throw new Error(`Cannot check proxy IP. Status code: ${response.status}`);
      }
    } catch (error) {
      throw new Error(`Error checking proxy IP: ${error.message}`);
    }
  }

  async makeRequest(
    url,
    method,
    data = {},
    options = {
      retries: 2,
      isAuth: false,
      extraHeaders: {},
      refreshToken: null,
    }
  ) {
    const { retries, isAuth, extraHeaders, refreshToken } = options;

    const headers = {
      ...this.headers,
      ...extraHeaders,
    };

    if (!isAuth && this.token) {
      headers["authorization"] = `Bearer ${this.token}`;
    }

    if (this.localItem?.cookie) {
      headers["cookie"] = `${this.localItem?.cookie}`;
    }

    let proxyAgent = null;
    if (settings.USE_PROXY) {
      proxyAgent = new HttpsProxyAgent(this.proxy);
    }
    let currRetries = 0,
      errorMessage = null,
      errorStatus = 0;

    do {
      try {
        const response = await axios({
          method,
          url,
          headers,
          timeout: 120000,
          ...(proxyAgent ? { httpsAgent: proxyAgent, httpAgent: proxyAgent } : {}),
          ...(method.toLowerCase() != "get" ? { data } : {}),
        });
        if (response?.data?.data) return { responseHeader: response.headers, status: response.status, success: true, data: response.data.data, error: null };
        return { responseHeader: response.headers, success: true, data: response.data, status: response.status, error: null };
      } catch (error) {
        errorStatus = error.status;
        errorMessage = error?.response?.data?.error || error?.response?.data || error.message;
        this.log(`Request failed: ${url} | Status: ${error.status} | ${JSON.stringify(errorMessage || {})}...`, "warning");

        if (error.message.includes("stream has been aborted")) {
          return { success: false, status: error.status, data: null, error: error.response.data.error || error.response.data.message || error.message };
        }

        if (error.status >= 400 && error.status < 500) {
          if (error.status == 401) {
            if (url.includes("/me")) {
              const result = await this.register();
            } else {
              const token = await this.getValidToken(true);
              if (!token) {
                process.exit(0);
              }
              this.token = token;
            }
            return await this.makeRequest(url, method, data, options);
            // return { status: error.status, success: false, error: errorMessage, data: null };
          } else if (error.status == 400) {
            // this.log(`Invalid request for ${url}, maybe have new update from server | contact: https://t.me/airdrophuntersieutoc to get new update!`, "error");
            return { success: false, status: error.status, error: errorMessage, data: null };
          } else if (error.status == 429) {
            this.log(`Rate limit ${JSON.stringify(errorMessage)}, waiting 60s to retries`, "warning");
            await sleep(60);
          } else return { status: error.status, success: false, error: errorMessage, data: null };
        }
        if (currRetries > retries) {
          return { status: error.status, success: false, error: errorMessage, data: null };
        }
        currRetries++;
        await sleep(5);
      }
    } while (currRetries <= retries);
    return { status: errorStatus, success: false, error: errorMessage, data: null };
  }

  getCookieData(setCookie) {
    try {
      if (!(setCookie?.length > 0)) return null;
      let cookie = [];
      const item = JSON.stringify(setCookie);

      const nonceMatch = item.match(/refresh_token=([^;]+)/);
      if (nonceMatch && nonceMatch[0]) {
        cookie.push(nonceMatch[0]);
      }
      const data = cookie.join(";");
      return cookie.length > 0 ? data : null;
    } catch (error) {
      this.log(`Error get cookie: ${error.message}`, "error");
      return null;
    }
  }

  async register(newWallet = this.localItem?.aa_address) {
    const payload = {
      registration_type_id: 1,
      user_account_id: "",
      user_account_name: "",
      eoa_address: this.itemData.address,
      smart_account_address: newWallet,
      referral_code: settings.REF_CODE || null,
    };
    return this.makeRequest(`${settings.BASE_URL_V2}/auth`, "post", payload, {});
  }

  encrypt() {
    const key = Buffer.from(settings.API_ID, "hex");
    const iv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);

    let ciphertext = cipher.update(this.wallet.address, "utf8", "hex") + cipher.final("hex");
    const authTag = cipher.getAuthTag();

    const result = Buffer.concat([iv, Buffer.from(ciphertext, "hex"), authTag]);
    return result.toString("hex");
  }

  async sigin(payload) {
    const res = await this.makeRequest(`${this.baseURL}/v2/signin`, "post", payload, {
      isAuth: true,
      extraHeaders: {
        authorization: `${this.encrypt()}`,
      },
    });
    const responseHeader = res?.responseHeader;
    if (responseHeader) {
      const cookie = responseHeader["set-cookie"];
      if (cookie?.length > 0) {
        res["cookie"] = cookie.join(";");
      }
    }
    return res;
  }

  async getUserData() {
    return this.makeRequest(`${this.baseURL_v2}/me`, "get");
  }

  async getBalance() {
    return this.makeRequest(`${this.baseURL_v2}/me/balance`, "get");
  }

  async getCheckin() {
    return this.makeRequest(`${this.baseURL}/userCenter/api/v1/ai/terminal/getSignInRecords`, "get");
  }

  async getQuizOnboard() {
    return this.makeRequest(`${this.baseURL}/v2/quiz/onboard/get?eoa=${this.itemData.address}`, "get");
  }

  async createQuiz() {
    const today = new Date();
    const year = today.getUTCFullYear();
    const month = String(today.getUTCMonth() + 1).padStart(2, "0");
    const day = String(today.getUTCDate()).padStart(2, "0");
    const title = `daily_quiz_${year}-${month}-${day}`;

    return this.makeRequest(`${this.baseURL}/v2/quiz/create`, "post", {
      title: title,
      num: 1,
      eoa: this.itemData.address,
    });
  }
  async getQuiz(id) {
    return this.makeRequest(`${this.baseURL}/v2/quiz/get?id=${id}&eoa=${this.itemData.address}`, "get");
  }
  async completeQuiz(payload) {
    return this.makeRequest(`${this.baseURL}/v2/quiz/onboard/submit`, "post", payload);
  }

  async completeDailyQuiz(payload) {
    return this.makeRequest(`${this.baseURL}/v2/quiz/submit`, "post", payload);
  }

  async sendMess(payload) {
    return this.makeRequest(`${this.baseURL_v2}/agent/inference`, "post", payload, {
      extraHeaders: {
        Accept: "text/event-stream",
      },
    });
  }

  async submitReceipt(payload) {
    return this.makeRequest(`${this.baseURL}/v2/submit_receipt`, "post", payload, {});
  }

  async stake(payload) {
    return this.makeRequest(`${this.baseURL_v2}/subnet/delegate`, "post", payload, {});
  }

  async getStakeInfo() {
    return this.makeRequest(`${this.baseURL_v2}/subnets?page=1&size=100`, "get");
  }

  async faucet() {
    this.log(`Solving captcha...`);
    const recaptchaToken = await solveCaptcha();
    if (!recaptchaToken) {
      return { success: false };
    }

    return this.makeRequest(
      `${this.baseURL_v2}/blockchain/faucet-transfer`,
      "post",
      {},
      {
        extraHeaders: {
          "x-recaptcha-token": recaptchaToken,
        },
      }
    );
  }

  async faucetTokens(tokenName) {
    this.log(`Solving captcha...`);
    const recaptchaToken = await solveCaptcha({
      websiteKey: "6LeNaK8qAAAAAHLuyTlCrZD_U1UoFLcCTLoa_69T",
      websiteURL: "https://faucet.gokite.ai",
    });
    if (!recaptchaToken) {
      return { success: false };
    }

    return this.makeRequest(
      `https://faucet.gokite.ai/api/sendToken`,
      "post",
      {
        address: this.itemData.address,
        token: "",
        v2Token: recaptchaToken,
        chain: "KITE",
        couponId: "",
        ...(token !== "KITE"
          ? {
              erc20: tokenName,
            }
          : {}),
      },
      {
        extraHeaders: {
          origin: "https://faucet.gokite.ai",
          referer: "https://faucet.gokite.ai/",
        },
      }
    );
  }

  async getValidToken(isNew = false) {
    const existingToken = this.token;
    const { isExpired: isExp, expirationDate } = isTokenExpired(existingToken);

    this.log(`Access token status: ${isExp ? "Expired".yellow : "Valid".green} | Acess token exp: ${expirationDate}`);
    if (existingToken && !isNew && !isExp) {
      this.log("Using valid token", "success");
      return existingToken;
    }

    this.log("No found token or experied, trying get new token...", "warning");
    const loginRes = await this.handleLogin();
    const data = loginRes.data;
    if (data?.access_token) {
      await saveJson(
        this.session_name,
        JSON.stringify({
          ...data,
          cookie: loginRes?.cookie || null,
        }),
        "localStorage.json"
      );
      this.localItem = data;
      return data.access_token;
    }
    this.log(`Can't get new token | ${JSON.stringify(loginRes)}...`, "warning");
    return null;
  }

  async handleStake(userData) {
    const { kite } = userData.balances;
    if (+kite < 1) return this.log(`Not enough kite to stake.`, "warning");
    let amount = getRandomNumber(settings.AMOUNT_STAKE[0], settings.AMOUNT_STAKE[1]);
    amount = Math.min(kite, 1);
    const resGET = await this.getStakeInfo();
    this.log(`Staking ${amount} KITE`);
    const subAddress = resGET.data[0]?.address || "0xc368ae279275f80125284d16d292b650ecbbff8d";
    // console.log(resGET.data);
    const res = await this.stake({
      subnet_address: subAddress,
      amount: amount,
    });
    if (res.success && res.data?.tx_hash) {
      this.log(`Stake ${amount} kite success | tx: ${res.data?.tx_hash}`, "success");
    } else {
      this.log(`Stake ${amount} kite failed | ${JSON.stringify(res)}`, "warning");
    }
  }
  async handleDailyQuiz() {
    const resCreate = await this.createQuiz();
    if (resCreate.success && resCreate.data?.quiz_id) {
      const resGet = await this.getQuiz(resCreate.data?.quiz_id);
      if (resGet.success) {
        const quests = resGet.data.question;
        for (const q of quests) {
          await sleep(1);
          this.log(`Compeleting quest: ${q.content}`);
          const payload = {
            quiz_id: resCreate.data?.quiz_id,
            question_id: q.question_id,
            answer: q.answer,
            finish: true,
            eoa: this.itemData.address,
          };
          const result = await this.completeDailyQuiz(payload);
          if (result.data?.result === "RIGHT") {
            this.log(`Completed daily quiz success!`, "success");
          } else {
            this.log(`Completed daily quiz failed! | ${JSON.stringify}`, "warning");
          }
        }
      }
    }
  }

  async handleLogin() {
    const payload = {
      eoa: this.itemData.address,
    };
    let resLogin = await this.sigin(payload);
    if (!resLogin.success && resLogin.status == 422) {
      this.log(`User not found, creating new user...`, "warning");
      const newWallet = ethers.Wallet.createRandom();
      payload["aa_address"] = newWallet.address;
      resLogin = await this.sigin(payload);
      if (resLogin.success) {
        this.token = resLogin.data.access_token;
        await this.register(newWallet.address);
      }
    }
    return resLogin;
  }

  async handleOnBoard() {
    const resGet = await this.getQuizOnboard();
    if (!resGet.success) return;
    const ques = resGet.data.question.filter((i) => i.user_answer != i.answer);
    for (const q of ques) {
      await sleep(1);
      const { question_id, content } = q;
      this.log(`Completeing quiz ${content}`);
      const payload = {
        question_id: question_id,
        answer: q.answer,
        finish: question_id == 4,
        eoa: this.itemData.address,
      };
      const result = await this.completeQuiz(payload);
      if (result.success) {
        this.log(`Completed quiz ${content} success!`, "success");
      } else {
        this.log(`Completed quiz ${content} failed! | ${JSON.stringify(result)}`, "warning");
      }
    }
  }

  generatePayloadMess() {
    const agent = getRandomElement(settings.AGENTS);
    let mess = getRandomElement(ProfessorQuestions);
    let service_id = settings.PROFESSOR_ID;

    switch (agent) {
      case "Professor":
        break;
      case "Crypto Buddy":
        mess = getRandomElement(Crypto_BuddyQuestions);
        service_id = settings.CRYPTO_BUDDY_ID;
        break;
      case "Sherlock":
        mess = getRandomElement(SherlockQuestions);
        service_id = settings.SELOCK_ID;
        break;
      default:
        mess = getRandomElement(ProfessorQuestions);
        service_id = settings.PROFESSOR_ID;
        break;
    }

    const payload = {
      service_id: service_id,
      subnet: "kite_ai_labs",
      stream: true,
      body: {
        stream: true,
        message: mess,
      },
    };
    return payload;
  }

  generateAnswer(initdata) {
    const dataLines = initdata.split("\n");
    let content = "";

    dataLines.forEach((line) => {
      if (line.startsWith("data:")) {
        const jsonData = line.slice(6).trim();

        if (jsonData === "[DONE]") {
          return;
        }

        try {
          const parsedData = JSON.parse(jsonData);
          const deltaContent = parsedData.choices[0].delta.content;
          if (deltaContent) {
            content += deltaContent;
          }
        } catch (e) {}
      }
    });
    return content;
  }
  async handleMess(userData) {
    const { smart_account_address } = userData.profile;
    let limit = Number(settings.AMOUNT_CHAT);
    let total = Number(settings.AMOUNT_CHAT);

    while (limit > 0) {
      const payload = this.generatePayloadMess();
      const mess = payload.body.message;
      this.log(`[${limit}/${total}] Sending mess: ${mess}`);
      const res = await this.sendMess(payload);
      if (res.success) {
        this.log(`[${limit}/${total}] Sent ${mess} success!`, "success");
        const answer = this.generateAnswer(res.data);
        const payloadSubmit = {
          address: smart_account_address,
          service_id: payload.service_id,
          input: [
            {
              type: "text/plain",
              value: mess,
            },
          ],
          output: [
            {
              type: "text/plain",
              value: answer,
            },
          ],
        };
        await this.submitReceipt(payloadSubmit);
      } else {
        this.log(`[${limit}/${total}] Sent message ${mess} failed | ${JSON.stringify(res)}`, "warning");
      }
      if (limit > 1) {
        const timeSleep = getRandomNumber(settings.DELAY_CHAT[0], settings.DELAY_CHAT[1]);
        this.log(`Sleeping for ${timeSleep} seconds to next message...`, "info");
        await sleep(timeSleep);
      }

      limit--;
    }
  }

  async handleSyncData() {
    this.log(`Sync data...`);
    let userData = { success: false, data: null, status: 0 },
      retries = 0;
    do {
      userData = await this.getUserData();
      if (userData?.success) break;
      retries++;
    } while (retries < 1 && userData.status !== 400);
    const blance = await this.getBalance();
    if (userData?.success) {
      const { profile, onboarding_quiz_completed, faucet_claimable, daily_quiz_completed } = userData.data;
      const { balances } = blance.data;
      userData.data["balances"] = balances;
      this.log(`Kite: ${balances["kite"]} | USDT: ${Number(balances["usdt"]).toFixed(4)} | Total points: ${profile?.total_xp_points || 0}`, "custom");
    } else {
      this.log("Can't sync new data...skipping", "warning");
    }
    return userData;
  }

  async handleFaucet() {
    const res = await this.faucet();
    if (res.success) {
      this.log(`Faucet success!`, "success");
    } else {
      this.log(`Faucet failed! | ${JSON.stringify(res)}`, "warning");
    }
    if (settings.AUTO_FAUCET_STABLE_COIN) {
      const list = ["USDT", "KITE"];
      for (const token of list) {
        await sleep(1);
        const resFaucet = await this.faucetTokens(token);
        if (resFaucet.success && resFaucet.data?.txHash) {
          this.log(`${resFaucet.data.message} | Tx: ${resFaucet.data?.txHash}`, "success");
        }
      }
    }
  }
  async runAccount() {
    const accountIndex = this.accountIndex;
    this.session_name = this.itemData.address;
    this.localItem = JSON.parse(this.localStorage[this.session_name] || "{}");
    this.token = this.localItem?.access_token;

    this.#set_headers();
    if (settings.USE_PROXY) {
      try {
        this.proxyIP = await this.checkProxyIP();
      } catch (error) {
        this.log(`Cannot check proxy IP: ${error.message}`, "warning");
        return;
      }
      const timesleep = getRandomNumber(settings.DELAY_START_BOT[0], settings.DELAY_START_BOT[1]);
      console.log(`=========Tài khoản ${accountIndex + 1} | ${this.proxyIP} | Bắt đầu sau ${timesleep} giây...`.green);
      await sleep(timesleep);
    }

    const token = await this.getValidToken();
    if (!token) return;
    this.token = token;

    const userData = await this.handleSyncData();
    if (userData.success) {
      const { profile, onboarding_quiz_completed, faucet_claimable, daily_quiz_completed } = userData.data;
      if (onboarding_quiz_completed === false) {
        this.log(`Starting onboard quiz...`);
        await this.handleOnBoard();
        await sleep(1);
      }
      if (faucet_claimable === true && settings.AUTO_FAUCET) {
        this.log(`Starting faucet...`);
        await this.handleFaucet();
        await sleep(1);
      }
      if (onboarding_quiz_completed === false) {
        this.log(`Starting daily quiz...`);
        await this.handleDailyQuiz();
        await sleep(1);
      }

      if (settings.AUTO_STAKE) {
        await this.handleStake(userData.data);
        await sleep(1);
      }

      if (settings.AUTO_CHAT) {
        await this.handleMess(userData.data);
        await sleep(1);
      }
    } else {
      return this.log("Can't get use info...skipping", "error");
    }
  }
}

async function runWorker(workerData) {
  const { itemData, accountIndex, proxy, hasIDAPI } = workerData;
  const to = new ClientAPI(itemData, accountIndex, proxy, hasIDAPI);
  try {
    await Promise.race([to.runAccount(), new Promise((_, reject) => setTimeout(() => reject(new Error("Timeout")), 24 * 60 * 60 * 1000))]);
    parentPort.postMessage({
      accountIndex,
    });
  } catch (error) {
    parentPort.postMessage({ accountIndex, error: error.message });
  } finally {
    if (!isMainThread) {
      parentPort.postMessage("taskComplete");
    }
  }
}

async function main() {
  console.clear();
  showBanner();
  const privateKeys = loadData("privateKeys.txt");
  const proxies = loadData("proxy.txt");

  if (privateKeys.length == 0 || (privateKeys.length > proxies.length && settings.USE_PROXY)) {
    console.log("Số lượng proxy và data phải bằng nhau.".red);
    console.log(`Data: ${privateKeys.length}`);
    console.log(`Proxy: ${proxies.length}`);
    process.exit(1);
  }
  if (!settings.USE_PROXY) {
    console.log(`You are running bot without proxies!!!`.yellow);
  }
  let maxThreads = settings.USE_PROXY ? settings.MAX_THEADS : settings.MAX_THEADS_NO_PROXY;

  const resCheck = await checkBaseUrl();
  if (!resCheck.endpoint) return console.log(`Không thể tìm thấy ID API, có thể lỗi kết nỗi, thử lại sau!`.red);
  console.log(`${resCheck.message}`.yellow);

  const data = privateKeys.map((val, index) => {
    const prvk = val.startsWith("0x") ? val : `0x${val}`;
    const wallet = new ethers.Wallet(prvk);
    const item = {
      address: wallet.address,
      privateKey: prvk,
    };
    new ClientAPI(item, index, proxies[index], resCheck.endpoint, {}).createUserAgent();
    return item;
  });
  await sleep(1);
  while (true) {
    let currentIndex = 0;
    const errors = [];
    while (currentIndex < data.length) {
      const workerPromises = [];
      const batchSize = Math.min(maxThreads, data.length - currentIndex);
      for (let i = 0; i < batchSize; i++) {
        const worker = new Worker(__filename, {
          workerData: {
            hasIDAPI: resCheck.endpoint,
            itemData: data[currentIndex],
            accountIndex: currentIndex,
            proxy: proxies[currentIndex % proxies.length],
          },
        });

        workerPromises.push(
          new Promise((resolve) => {
            worker.on("message", (message) => {
              if (message === "taskComplete") {
                worker.terminate();
              }
              if (settings.ENABLE_DEBUG) {
                console.log(message);
              }
              resolve();
            });
            worker.on("error", (error) => {
              console.log(`Lỗi worker cho tài khoản ${currentIndex}: ${error?.message}`);
              worker.terminate();
              resolve();
            });
            worker.on("exit", (code) => {
              worker.terminate();
              if (code !== 0) {
                errors.push(`Worker cho tài khoản ${currentIndex} thoát với mã: ${code}`);
              }
              resolve();
            });
          })
        );

        currentIndex++;
      }

      await Promise.all(workerPromises);

      if (errors.length > 0) {
        errors.length = 0;
      }

      if (currentIndex < data.length) {
        await new Promise((resolve) => setTimeout(resolve, 3000));
      }
    }

    await sleep(3);
    console.log(`=============${new Date().toLocaleString()} | Hoàn thành tất cả tài khoản | Chờ ${settings.TIME_SLEEP} phút=============`.magenta);
    showBanner();
    await sleep(settings.TIME_SLEEP * 60);
  }
}

if (isMainThread) {
  main().catch((error) => {
    console.log("Lỗi rồi:", error);
    process.exit(1);
  });
} else {
  runWorker(workerData);
}
