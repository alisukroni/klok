const { v4: uuidv4 } = require("uuid");
const { Wallet, ethers } = require("ethers");
const fs = require("fs");
const path = require("path");
const axios = require("axios");
const { HttpsProxyAgent } = require("https-proxy-agent");
const { SocksProxyAgent } = require("socks-proxy-agent");
const colors = require("colors");
const { loadData, saveJson, getRandomElement, getRandomNumber, sleep, randomDelay } = require("./utils.js");
const { config } = require("./config.js");
const readline = require("readline");
const questions = loadData("questions.txt");

function showBanner() {
  console.log(colors.yellow("Tool được phát triển bởi nhóm tele Airdrop Hunter Siêu Tốc (https://t.me/airdrophuntersieutoc)"));
}
function log(msg, type = "info") {
  const timestamp = new Date().toLocaleTimeString();
  switch (type) {
    case "success":
      console.log(`[${timestamp}] [✓] ${msg}`.green);
      break;
    case "custom":
      console.log(`[${timestamp}] [*] ${msg}`.magenta);
      break;
    case "error":
      console.log(`[${timestamp}] [✗] ${msg}`.red);
      break;
    case "warning":
      console.log(`[${timestamp}] [!] ${msg}`.yellow);
      break;
    default:
      console.log(`[${timestamp}] [ℹ] ${msg}`.blue);
  }
}

function getRandomMessage() {
  return getRandomElement(questions);
}

function getRandomInterval() {
  return getRandomNumber(config.DELAY_CHAT[0], config.DELAY_CHAT[1]) * 1000;
}

async function checkProxyIP(proxy) {
  try {
    const proxyAgent = new HttpsProxyAgent(proxy);
    const response = await axios.get("https://api.ipify.org?format=json", {
      httpsAgent: proxyAgent,
      timeout: 10000,
    });

    if (response.status === 200) {
      return response.data.ip;
    } else {
      throw new Error(`Không thể kiểm tra IP của proxy. Status code: ${response.status}`);
    }
  } catch (error) {
    throw new Error(`Error khi kiểm tra IP của proxy: ${error.message}`);
  }
}

function createApiClient(token, proxy) {
  const proxyAgent = proxy ? new HttpsProxyAgent(proxy) : null;

  return axios.create({
    baseURL: config.API_BASE_URL,
    headers: {
      "x-session-token": token,
      accept: "*/*",
      "accept-encoding": "gzip, deflate, br, zstd",
      "accept-language": "en-US,en;q=0.9",
      origin: "https://klokapp.ai",
      referer: "https://klokapp.ai/",
      "sec-ch-ua": '"Not(A:Brand";v="99", "Microsoft Edge";v="133", "Chromium";v="133"',
      "sec-ch-ua-mobile": "?0",
      "sec-ch-ua-platform": '"Windows"',
      "sec-fetch-dest": "empty",
      "sec-fetch-mode": "cors",
      "sec-fetch-site": "same-site",
      "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36 Edg/133.0.0.0",
    },
    httpsAgent: proxyAgent,
    timeout: 30000,
  });
}

async function resetToken() {
  fs.writeFileSync("token.json", JSON.stringify({}), "utf8", (err) => {
    if (err) {
      console.error("Error resetting tokens.json, please reset to {} in file tokens.json and run bot again: ".red, err);
    } else {
      console.log("tokens.json has been reset to {}".green);
    }
  });
}

async function checkRateLimit(apiClient, accountIndex) {
  try {
    const response = await apiClient.get("/rate-limit");
    const rateData = response.data;

    if (rateData.remaining === 0) {
      const resetTimeMinutes = Math.ceil(rateData.reset_time / 60);
      return {
        hasRemaining: false,
        resetTime: rateData.reset_time,
        remaining: 0,
      };
    }

    return {
      hasRemaining: true,
      resetTime: 0,
      remaining: rateData.remaining,
    };
  } catch (error) {
    if (error.status == 401) {
      await resetToken();
      await sleep(1);
      process.exit(1);
    }
    log(`Account ${accountIndex + 1}: Error checking limit: ${error.response?.status || error.message}`, "error");
    return {
      hasRemaining: false,
      resetTime: 0,
      remaining: 0,
    };
  }
}

async function getThreads(apiClient) {
  try {
    const response = await apiClient.get("/threads");
    return response.data.data;
  } catch (error) {
    if (error.status == 401) {
      await resetToken();
      await sleep(1);
      process.exit(1);
    }
    log(`Error fetching thread list: ${error.response?.status || error.message}`, "error");
    return [];
  }
}

async function createNewThread(apiClient, message) {
  const threadId = uuidv4();
  const chatData = {
    id: threadId,
    title: "",
    messages: [
      {
        role: "user",
        content: message,
      },
    ],
    sources: [],
    model: "llama-3.3-70b-instruct",
    created_at: new Date().toISOString(),
    language: "english",
  };

  try {
    const response = await apiClient.post("/chat", chatData);
    log(`New conversation created successfully with ID: ${threadId}`, "success");
    return { id: threadId };
  } catch (error) {
    if (error.message.includes("stream has been aborted")) {
      return { id: threadId };
    }
    log(`Unable to create new conversation: ${error.response?.status || error.message}`, "error");
    return null;
  }
}

async function sendMessageToThread(apiClient, threadId, message) {
  try {
    const chatData = {
      id: threadId,
      title: "",
      messages: [
        {
          role: "user",
          content: message,
        },
      ],
      sources: [],
      model: "llama-3.3-70b-instruct",
      created_at: new Date().toISOString(),
      language: "english",
    };

    const response = await apiClient.post("/chat", chatData);
    log(`Message sent successfully to thread: ${threadId}`, "success");
    return response.data;
  } catch (error) {
    if (error.status == 401) {
      await resetToken();
      await sleep(1);
      process.exit(1);
    }
    if (error.message.includes("stream has been aborted")) {
      return true;
    }
    log(`Error sending message: ${error.response?.status || error.message}`, "error");
    return null;
  }
}

async function checkPoints(apiClient, accountIndex, proxyIP = "Unknown") {
  try {
    const response = await apiClient.get("/points");
    const pointsData = response.data;

    log(`Account ${accountIndex + 1} | IP: ${proxyIP} | Points: ${pointsData.total_points || 0}`, "custom");
    return pointsData;
  } catch (error) {
    if (error.status == 401) {
      await resetToken();
      await sleep(1);
      process.exit(1);
    }
    log(`Error reading points for account ${accountIndex + 1}: ${error.response?.status || error.message}`, "error");
    return null;
  }
}

async function handleAccount(token, proxy, accountIndex) {
  log(`Processing account ${accountIndex + 1}...`);

  let proxyIP = "Unknown";
  try {
    proxyIP = await checkProxyIP(proxy);
    log(`Account ${accountIndex + 1}: Using proxy IP: ${proxyIP}`, "success");
  } catch (error) {
    log(`Account ${accountIndex + 1}: Unable to check proxy IP: ${error.message}`, "warning");
  }

  const apiClient = createApiClient(token, proxy);
  let currentThreadId = null;

  const pointsData = await checkPoints(apiClient, accountIndex, proxyIP);

  const rateLimitInfo = await checkRateLimit(apiClient, accountIndex);
  if (!rateLimitInfo.hasRemaining) {
    return {
      token,
      proxy,
      proxyIP,
      apiClient,
      currentThreadId: null,
      accountIndex,
      rateLimited: true,
      resetTime: rateLimitInfo.resetTime,
      failedAttempts: 0,
      points: pointsData?.total_points || 0,
      remainingChats: rateLimitInfo.remaining,
    };
  }

  const threads = await getThreads(apiClient);
  if (threads.length > 0) {
    currentThreadId = threads[0].id;
    log(`Account ${accountIndex + 1}: Using existing conversation: ${currentThreadId}`, "success");
  } else {
    const newThread = await createNewThread(apiClient, "Starting new conversation");
    if (newThread) {
      currentThreadId = newThread.id;
      log(`Account ${accountIndex + 1}: Started new conversation: ${currentThreadId}`, "success");
    }
  }

  return {
    token,
    proxy,
    proxyIP,
    apiClient,
    currentThreadId,
    accountIndex,
    rateLimited: false,
    resetTime: 0,
    failedAttempts: 0,
    lastRateLimitCheck: Date.now(),
    points: pointsData?.total_points || 0,
    remainingChats: rateLimitInfo.remaining,
  };
}

function createSiweMessage(address) {
  const nonce = ethers.hexlify(ethers.randomBytes(32)).slice(2);
  const timestamp = new Date().toISOString();
  return (
    `klokapp.ai wants you to sign in with your Ethereum account:\n${address}\n\n\n` + `URI: https://klokapp.ai/\n` + `Version: 1\n` + `Chain ID: 1\n` + `Nonce: ${nonce}\n` + `Issued At: ${timestamp}`
  );
}

function getProxyAgent(proxy) {
  try {
    if (proxy.startsWith("socks://")) {
      return new SocksProxyAgent(randomProxy);
    } else {
      return new HttpsProxyAgent(randomProxy);
    }
  } catch (error) {
    return null;
  }
}

async function getNewToken(wallet, agent) {
  const address = wallet.address;
  const message = createSiweMessage(address);
  console.log(`📝 Signing Message for ${address}`.blue);
  const signedMessage = await wallet.signMessage(message);
  const payload = { signedMessage, message, referral_code: config.REFERRAL_CODE };

  try {
    const response = await axios.post(`${config.API_BASE_URL}/verify`, payload, {
      headers: {
        "Content-Type": "application/json",
        "User-Agent": "Mozilla/5.0",
        Origin: "https://klokapp.ai",
        Referer: "https://klokapp.ai/",
      },
      httpAgent: agent, // Use the agent for the request
    });
    if (response.data.message == "Verification successful") {
      console.log(`✅ Login ${address} success!`);
      const token = response.data.session_token;
      saveJson(address, token, "tokens.json");
      return token;
    } else {
      console.log(`Login ${address} failed!`.yellow, JSON.stringify(response.data));
    }
  } catch (error) {
    console.error(`❌ Gagal mendaftar ${address}: `.red, error.response ? error.response.data : error.message);
  }
  return null;
}

async function runBot() {
  showBanner();
  const tokens = require("./tokens.json");
  const proxies = loadData("proxy.txt");
  const privateKeys = loadData("privateKeys.txt");

  if (privateKeys.length > proxies.length) {
    log(`The number of privateKeys (${privateKeys.length}) and proxies (${proxies.length}) do not match. Please check again.`, "error");
    process.exit(1);
  }

  const accountPromises = privateKeys.map(async (privateKey, index) => {
    const formattedKey = privateKey.startsWith("0x") ? privateKey : `0x${privateKey}`;
    const proxy = proxies[index];
    const agent = getProxyAgent(proxy);
    const wallet = new ethers.Wallet(formattedKey);
    const address = wallet.address;

    let token = tokens[address];
    if (!token) {
      console.log(`Token not found for wallet: ${address}, logging...`.yellow);
      token = await getNewToken(wallet, agent);
    }

    if (!token) {
      console.log(`Token not found for wallet: ${address}, skipping...`.yellow);
      return null; // Return null to filter out later
    }

    const timeSleep = getRandomNumber(config.DELAY_START_BOT[0], config.DELAY_START_BOT[1]);
    console.log(`[${address}] Waiting ${timeSleep}s to continue process...`.blue);
    await sleep(timeSleep);

    try {
      return await handleAccount(token, proxy, index);
    } catch (error) {
      log(`Error processing account ${index + 1}: ${error.message}`, "error");
      return {
        token,
        proxy,
        proxyIP: "Error",
        apiClient: null,
        currentThreadId: null,
        accountIndex: index,
        rateLimited: true,
        resetTime: 0,
        failedAttempts: 0,
        hasError: true,
        points: 0,
        remainingChats: 0,
      };
    }
  });

  // Wait for all account promises to resolve
  const accounts = (await Promise.all(accountPromises)).filter((account) => account !== null);

  async function processAccounts() {
    let allAccountsLimited = true;
    let minResetTime = 24 * 60 * 60;

    const accountPromises = accounts.map(async (account) => {
      if (account.hasError) {
        log(`Skipping account ${account.accountIndex + 1} due to previous error`, "warning");
        return;
      }
      const timeSleep = getRandomNumber(config.DELAY_START_BOT[0], config.DELAY_START_BOT[1]);
      console.log(`[${address}] Waiting ${timeSleep}s to continue process...`.blue);
      await sleep(timeSleep);
      try {
        const apiClient = createApiClient(account.token, account.proxy);
        account.apiClient = apiClient;
        await randomDelay();
        const rateLimitInfo = await checkRateLimit(account.apiClient, account.accountIndex);
        account.rateLimited = !rateLimitInfo.hasRemaining;
        account.resetTime = rateLimitInfo.resetTime;
        account.remainingChats = rateLimitInfo.remaining;
        account.lastRateLimitCheck = Date.now();

        if (!account.rateLimited) {
          allAccountsLimited = false;
        } else if (account.resetTime > 0 && account.resetTime < minResetTime) {
          minResetTime = account.resetTime;
          return;
        }

        if (account.rateLimited) return;
        await randomDelay();
        const pointsBefore = await checkPoints(account.apiClient, account.accountIndex, account.proxyIP);
        if (!pointsBefore || pointsBefore.total_points <= 0) {
          log(`Account ${account.accountIndex + 1}: No points available...`, "warning");
          return;
        }

        account.points = pointsBefore.total_points;

        if (!account.currentThreadId) {
          log(`Account ${account.accountIndex + 1}: No active conversation available. Creating a new conversation...`, "warning");
          const newThread = await createNewThread(apiClient, "Starting new conversation");
          if (newThread) {
            account.currentThreadId = newThread.id;
            account.failedAttempts = 0;
          } else {
            return;
          }
        }

        const message = getRandomMessage();
        log(`Account ${account.accountIndex + 1}: Sending message: "${message}"`, "info");
        await randomDelay();
        const result = await sendMessageToThread(apiClient, account.currentThreadId, message);

        const rateLimitAfter = await checkRateLimit(apiClient, account.accountIndex);
        account.remainingChats = rateLimitAfter.remaining;
        await randomDelay();
        const pointsAfter = await checkPoints(apiClient, account.accountIndex, account.proxyIP);

        if (!result) {
          account.failedAttempts++;
          log(`Account ${account.accountIndex + 1}: No response. Bot ignored attempt ${account.failedAttempts}/${config.MAX_FAILED_ATTEMPTS}`, "warning");

          if (account.failedAttempts >= config.MAX_FAILED_ATTEMPTS) {
            log(`Account ${account.accountIndex + 1}: Bot ignored ${config.MAX_FAILED_ATTEMPTS} consecutive times. Creating a new conversation.`, "warning");
            account.currentThreadId = null;
            account.failedAttempts = 0;
          }
        } else {
          if (pointsAfter && pointsBefore && pointsAfter.total_points <= pointsBefore.total_points) {
            log(`Account ${account.accountIndex + 1}: Points did not increase after sending the message. Creating a new conversation.`, "warning");
            account.currentThreadId = null;
          } else {
            log(`Account ${account.accountIndex + 1}: Successfully received response. Current points: ${pointsAfter ? pointsAfter.total_points : "Unknown"}`, "success");
            account.failedAttempts = 0;
            account.points = pointsAfter ? pointsAfter.total_points : account.points;
          }
        }
      } catch (error) {
        log(`Error processing account ${account.accountIndex + 1}: ${error.message}`, "error");
        try {
          account.proxyIP = await checkProxyIP(account.proxy);
          log(`Account ${account.accountIndex + 1}: Refreshed proxy IP: ${account.proxyIP}`, "success");
        } catch (proxyError) {
          log(`Account ${account.accountIndex + 1}: Proxy may be faulty: ${proxyError.message}`, "warning");
        }
      }
    });

    // Wait for all account promises to complete
    await Promise.all(accountPromises);

    if (allAccountsLimited) {
      log("All accounts have reached their limits. Waiting for some time before trying again.", "warning");

      if (minResetTime < 24 * 60 * 60 && minResetTime > 0) {
        log(`Waiting ${Math.ceil(minResetTime / 60)} minutes until rate limit resets...`, "custom");
        await sleep(minResetTime);
      } else {
        log("Waiting 24 hours before trying again...", "custom");
        const waitSeconds = 86400;
        await sleep(waitSeconds);
      }
    } else {
      const nextInterval = getRandomInterval();
      log(`The next conversation will take place in ${nextInterval / 1000} seconds`, "info");
      await sleep(nextInterval / 1000);
    }

    // Call processAccounts again to continue processing
    await processAccounts();
  }

  // Initial call to processAccounts
  await processAccounts();
}

runBot().catch((error) => {
  log(`Bot crashed: ${error}`, "error");
  process.exit(1);
});
