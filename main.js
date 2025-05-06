const fs = require("fs");
const path = require("path");
const axios = require("axios");
const colors = require("colors");
const { HttpsProxyAgent } = require("https-proxy-agent");
const readline = require("readline");
const user_agents = require("./config/userAgents");
const settings = require("./config/config.js");
const { sleep, loadData, getRandomNumber, saveToken, isTokenExpired, saveJson, updateEnv, decodeJWT, getRandomElement } = require("./utils.js");
const { Worker, isMainThread, parentPort, workerData } = require("worker_threads");
const { checkBaseUrl } = require("./checkAPI");
const { headers } = require("./core/header.js");
const { showBanner } = require("./core/banner.js");
const localStorage = require("./localStorage.json");
const { v4: uuidv4 } = require("uuid");
const { Wallet, ethers } = require("ethers");
const { solveCaptcha } = require("./captcha.js");
const questions = loadData("questions.txt");

class ClientAPI {
  constructor(itemData, accountIndex, proxy, baseURL, tokens) {
    this.headers = headers;
    this.baseURL = baseURL;
    this.itemData = itemData;
    this.accountIndex = accountIndex;
    this.proxy = proxy;
    this.proxyIP = null;
    this.session_name = null;
    this.session_user_agents = this.#load_session_data();
    this.token = tokens[this.session_name] || null;
    this.tokens = tokens;
    this.localStorage = localStorage;
    this.wallet = new ethers.Wallet(this.itemData);
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
      this.session_name = this.wallet.address;
      this.#get_user_agent();
    } catch (error) {
      this.log(`Can't create user agent: ${error.message}`, "error");
      return;
    }
  }

  async log(msg, type = "info") {
    const accountPrefix = `[Account ${this.accountIndex + 1}][${this.wallet.address}]`;
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
      retries: 1,
      isAuth: false,
    }
  ) {
    const { retries, isAuth } = options;

    const headers = {
      ...this.headers,
    };

    if (!isAuth) {
      headers["x-session-token"] = this.token;
    }

    let proxyAgent = null;
    if (settings.USE_PROXY) {
      proxyAgent = new HttpsProxyAgent(this.proxy);
    }
    let currRetries = 0,
      success = false;
    do {
      try {
        const response = await axios({
          method,
          url: `${url}`,
          data,
          headers,
          httpsAgent: proxyAgent,
          timeout: 30000,
        });
        success = true;
        if (response?.data?.data) return { status: response.status, success: true, data: response.data.data };
        return { success: true, data: response.data, status: response.status };
      } catch (error) {
        if (error.message.includes("stream has been aborted")) {
          return { success: false, status: error.status, data: null, error: error.response.data.error || error.response.data.message || error.message };
        }
        if (error.status == 401) {
          const token = await this.getValidToken(true);
          if (!token) {
            process.exit(1);
          }
          this.token = token;
          return this.makeRequest(url, method, data, options);
        }
        if (error.status == 400) {
          console.log(error.response.data);
          this.log(`$Invalid request for ${url}, maybe have new update from server | contact: https://t.me/airdrophuntersieutoc to get new update!`, "error");
          return { success: false, status: error.status, error: error.response.data.error || error.response.data.message || error.message };
        }
        this.log(`Yêu cầu thất bại: ${url} | ${error.message} | đang thử lại...`, "warning");
        success = false;
        await sleep(settings.DELAY_BETWEEN_REQUESTS);
        if (currRetries == retries) return { status: error.status, success: false, error: error.message };
      }
      currRetries++;
    } while (currRetries <= retries && !success);
    return { status: 500, success: false, error: "Unknow" };
  }

  async auth() {
    let token = null;
    if (settings.USE_CAPTCHA) {
      token = await solveCaptcha();
      if (!token) {
        this.log("Captcha not solved, skipping...", "warning");
        return { success: false, data: null };
      }
    }
    const wallet = this.wallet;
    const nonce = ethers.hexlify(ethers.randomBytes(32)).slice(2);
    const timestamp = new Date().toISOString();
    const message = `klokapp.ai wants you to sign in with your Ethereum account:\n${wallet.address}\n\n\nURI: https://klokapp.ai/\nVersion: 1\nChain ID: 1\nNonce: ${nonce}\nIssued At: ${timestamp}`;
    const signedMessage = await wallet.signMessage(message);
    const payload = {
      signedMessage,
      message,
      referral_code: settings.REF_CODE,
      ...(token ? { recaptcha_token: token } : {}),
    };
    return this.makeRequest(`${this.baseURL}/verify`, "post", payload, { isAuth: true });
  }

  async getUserData() {
    return this.makeRequest(`${this.baseURL}/me`, "get");
  }

  async getBalance() {
    return this.makeRequest(`${this.baseURL}/points`, "get");
  }

  async getModels() {
    return this.makeRequest(`${this.baseURL}/models`, "get");
  }

  async getRateLimit() {
    return this.makeRequest(`${this.baseURL}/rate-limit`, "get");
  }

  async getThreads() {
    return this.makeRequest(`${this.baseURL}/threads`, "get");
  }

  async getTask(id) {
    return this.makeRequest(`${this.baseURL}/points/action/${id}`, "get");
  }

  async completeTask(id) {
    return this.makeRequest(`${this.baseURL}/points/action/${id}`, "post");
  }

  async getRefs() {
    return this.makeRequest(`${this.baseURL}/referral/stats`, "get");
  }

  async sendMessage(payload) {
    return this.makeRequest(`${this.baseURL}/chat`, "post", payload);
  }

  async createNewThread(payload) {
    return this.makeRequest(`${this.baseURL}/chat`, "post", payload);
  }

  async handleNewThread(message, model) {
    this.log(`Creating new thread | Model: ${model}`, "warning");
    const payload = {
      id: uuidv4(),
      title: "New Chat",
      messages: [
        {
          role: "user",
          content: message,
        },
      ],
      sources: [],
      model: model,
      created_at: new Date().toISOString(),
      language: "english",
    };
    const resultNewThread = await this.createNewThread(payload);
    if (resultNewThread.success) {
      this.log(`Create new thread ${JSON.stringify(resultNewThread.data) || {}} success!`, "success");
      return true;
    }
    return false;
  }

  async handleThreads() {
    let model = "llama-3.3-70b-instruct";
    let currentThread = null;
    let amountChat = 0;

    const dataModels = await this.getModels();
    if (dataModels.success && dataModels.data?.length > 0) {
      model = getRandomElement(dataModels.data).name;
    }

    //lay ds thead
    const threads = await this.getThreads();
    if (!threads.success) {
      this.log("Can't get threads", "error");
      return;
    }
    currentThread = getRandomElement(threads.data);
    const message = getRandomElement(questions);

    //khong co thread nao tao moi
    if (!currentThread) {
      const res = await this.handleNewThread(message, model);
      if (res) return await this.handleThreads();
    }

    const limitData = await this.getRateLimit();
    if (limitData.success) {
      const { current_usage, limit, remaining, reset_time } = limitData.data;
      amountChat = remaining;
      if (remaining == 0 || current_usage >= limit) {
        this.log(`Rate limit remaining: ${remaining}/${limit} | Reset time: ${Math.ceil(reset_time / 60)} minutes`, "warning");
        return;
      }
    }

    this.log(`Starting chat...`, "info");
    while (amountChat > 0) {
      amountChat--;
      const newMessage = getRandomElement(questions);
      const newPayload = {
        id: currentThread.id,
        title: currentThread.title,
        messages: [
          {
            role: "user",
            content: newMessage,
          },
        ],
        sources: [],
        model: model,
        created_at: new Date().toISOString(),
        language: "english",
      };
      const result = await this.sendMessage(newPayload);
      if (result.success) {
        this.log(`Send message: ${newMessage} `, "success");
        amountChat--;
      } else {
        if (JSON.stringify(result.error || {}).includes("stream has been aborted")) {
          if (threads.data?.length && threads.data?.length < 10) {
            const res = await this.handleNewThread(message, model);
            if (res) return await this.handleThreads();
          } else {
            this.log(`Send message ${newMessage} failed | ${JSON.stringify(result.error || {})}`, "warning");
          }
        } else this.log(`Send message ${newMessage} failed | ${JSON.stringify(result.error || {})}`, "warning");
      }
      const timeSleep = getRandomNumber(settings.DELAY_CHAT[0], settings.DELAY_CHAT[1]);
      this.log(`Sleeping for ${timeSleep} seconds to next message...`, "info");
      await sleep(timeSleep);
    }
  }

  async handleTasks() {
    const ids = settings.TASKS_ID;
    for (const id of ids) {
      // if (this.localStorage[this.session_name]?.tasksCompleted === id) continue;
      const isCompleted = await this.getTask(id);
      if (isCompleted?.data?.has_completed === false) {
        this.log(`Trying complete task ${id}`);
        const result = await this.completeTask(id);
        if (result.success) {
          this.log(`Claim task ${id} success | ${JSON.stringify(result.data || {})}`, "success");
          // saveJson(this.session_name, id, "localStorage.json");
        }
      } else if (isCompleted?.data?.has_completed === true) {
      } else {
        this.log(`Can't get task ${id} | ${JSON.stringify(isCompleted || {})}`, "warning");
      }
    }
  }

  async getValidToken(isNew = false) {
    const existingToken = this.token;
    // const isExp = isTokenExpired(existingToken);
    if (existingToken && !isNew) {
      this.log("Using valid token", "success");
      return existingToken;
    } else {
      this.log("No found token or experied, trying get new token...", "warning");
      const newToken = await this.auth();
      if (newToken.success && newToken.data?.session_token) {
        saveJson(this.session_name, newToken.data.session_token, "tokens.json");
        return newToken.data.session_token;
      }
      this.log("Can't get new token...", "warning");
      return null;
    }
  }

  async handleSyncData() {
    let userData = { success: false, data: null },
      retries = 0;
    do {
      userData = await this.getUserData();
      if (userData?.success) break;
      retries++;
    } while (retries < 2);
    const balanceData = await this.getBalance();
    if (userData.success && balanceData.success) {
      this.log(`Points: ${balanceData.data.total_points} | Tier: ${userData.data.tier} | Details: ${JSON.stringify(balanceData.data.points || {})}`, "custom");
    } else {
      return this.log("Can't sync new data...skipping", "warning");
    }
    return userData;
  }

  async runAccount() {
    const accountIndex = this.accountIndex;
    this.session_name = this.wallet.address;
    this.token = this.tokens[this.session_name];
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
      await this.handleTasks();
      await sleep(1);
      await this.handleThreads();
      await sleep(1);
      await this.handleSyncData();
    } else {
      return this.log("Can't get use info...skipping", "error");
    }
  }
}

async function runWorker(workerData) {
  const { itemData, accountIndex, proxy, hasIDAPI, tokens } = workerData;
  const to = new ClientAPI(itemData, accountIndex, proxy, hasIDAPI, tokens);
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
  showBanner();
  // fs.writeFile("./tokens.json", JSON.stringify({}), (err) => {});
  // await sleep(1);
  const privateKeys = loadData("privateKeys.txt");
  const proxies = loadData("proxy.txt");
  let tokens = require("./tokens.json");
  const data = privateKeys.map((item) => (item.startsWith("0x") ? item : `0x${item}`)).reverse();
  if (data.length == 0 || (data.length > proxies.length && settings.USE_PROXY)) {
    console.log("Số lượng proxy và data phải bằng nhau.".red);
    console.log(`Data: ${data.length}`);
    console.log(`Proxy: ${proxies.length}`);
    process.exit(1);
  }
  if (!settings.USE_PROXY) {
    console.log(`You are running bot without proxies!!!`.yellow);
  }
  let maxThreads = settings.USE_PROXY ? settings.MAX_THEADS : settings.MAX_THEADS_NO_PROXY;

  const { endpoint, message } = await checkBaseUrl();
  if (!endpoint) return console.log(`Không thể tìm thấy ID API, thử lại sau!`.red);
  console.log(`${message}`.yellow);
  // process.exit();
  data.map((val, i) => new ClientAPI(val, i, proxies[i], endpoint, tokens).createUserAgent());
  await sleep(1);
  while (true) {
    tokens = require("./tokens.json");
    let currentIndex = 0;
    const errors = [];
    while (currentIndex < data.length) {
      const workerPromises = [];
      const batchSize = Math.min(maxThreads, data.length - currentIndex);
      for (let i = 0; i < batchSize; i++) {
        const worker = new Worker(__filename, {
          workerData: {
            hasIDAPI: endpoint,
            itemData: data[currentIndex],
            accountIndex: currentIndex,
            proxy: proxies[currentIndex % proxies.length],
            tokens,
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
              console.log(`Lỗi worker cho tài khoản ${currentIndex}: ${error.message}`);
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
