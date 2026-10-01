require("dotenv").config();
const express = require("express");
const session = require("express-session");
const path = require("path");
const fs = require("fs/promises");
const crypto = require("crypto");

const app = express();
const port = 3000;
const accountsFile = path.join(__dirname, "accounts.json");

app.use(express.urlencoded({ extended: false, limit: "10kb" }));
app.use(express.json({ limit: "10kb" }));

app.use(session({
  secret: crypto.randomBytes(32).toString("hex"),
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    sameSite: "lax",
    secure: false,
    maxAge: 60 * 60 * 1000
  }
}));

const pages = [
  "index.html",
  "accounts.html",
  "about.html",
  "contact.html",
  "help.html",
  "privacy.html",
  "signin.html",
  "open-account.html",
"admin-login.html"
];

async function readAccounts() {
  try {
    const fileContents = await fs.readFile(accountsFile, "utf8");
    return JSON.parse(fileContents);
  } catch (error) {
    if (error.code === "ENOENT") {
      return [];
    }
    throw error;
  }
}

function createAccountNumber(accounts) {
  let accountNumber;

  do {
    accountNumber = String(crypto.randomInt(1000000000, 10000000000));
  } while (accounts.some((account) => account.accountNumber === accountNumber));

  return accountNumber;
}

function escapeHtml(value) {
  return String(value).replace(/[&<>"']/g, (character) => {
    const replacements = {
      "&": "&amp;",
      "<": "&lt;",
      ">": "&gt;",
      '"': "&quot;",
      "'": "&#39;"
    };

    return replacements[character];
  });
}

function messagePage(title, message) {
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>${title} | NovaBank</title>
  <link rel="stylesheet" href="/style.css">
</head>
<body>
  <header class="site-header">
    <a class="brand wordmark" href="/" aria-label="NovaBank home">
      <span>NOVA</span><span class="wordmark-bank">BANK</span>
    </a>
  </header>
  <main class="application-layout">
    <section class="application-card">
      <h1>${title}</h1>
      <p>${message}</p>
      <a class="button" href="/">Return to NovaBank</a>
    </section>
  </main>
</body>
</html>`;
}

app.get("/api/health", (req, res) => {
  res.json({ status: "NovaBank server is running" });
});

app.post("/api/register", async (req, res) => {
  const fullName = String(req.body["full-name"] || "").trim();
  const email = String(req.body.email || "").trim().toLowerCase();
  const accountType = String(req.body["account-type"] || "");
  const password = String(req.body.password || "");

  if (!fullName || !email || !accountType || !password) {
    return res.status(400).send(
      messagePage("Please complete every field", "Go back and fill in all the requested information.")
    );
  }

  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
    return res.status(400).send(
      messagePage("Check your email address", "Enter a valid email address and try again.")
    );
  }

  if (!["checking", "savings"].includes(accountType)) {
    return res.status(400).send(
      messagePage("Choose an account", "Select Checking or Savings and try again.")
    );
  }

  if (password.length < 12 || password.length > 128) {
    return res.status(400).send(
      messagePage("Check your password", "Use a password between 12 and 128 characters.")
    );
  }

  try {
    const accounts = await readAccounts();

    if (accounts.some((account) => account.email === email)) {
      return res.status(409).send(
        messagePage("Email already registered", "Try signing in with this email address.")
      );
    }

    const salt = crypto.randomBytes(16).toString("hex");
    const passwordHash = crypto.scryptSync(password, salt, 64).toString("hex");

    accounts.push({
  id: crypto.randomUUID(),
  fullName,
  email,
  accountType,
  status: "pending",
  passwordHash: `${salt}:${passwordHash}`,
  createdAt: new Date().toISOString()
});

    await fs.writeFile(accountsFile, JSON.stringify(accounts, null, 2), "utf8");

    res.status(201).send(
      messagePage("Your application has been received", "Your NovaBank application was saved.")
    );
  } catch (error) {
    console.error(error);
    res.status(500).send(
      messagePage("Something went wrong", "Please try again later.")
    );
  }
});

app.post("/api/login", async (req, res) => {
  const email = String(req.body.email || "").trim().toLowerCase();
  const password = String(req.body.password || "");

  try {
    const accounts = await readAccounts();
    const account = accounts.find((savedAccount) => savedAccount.email === email);

    if (!account || !account.passwordHash) {
      return res.status(401).send(
        messagePage("Sign-in details not recognized", "Check your email and password, then try again.")
      );
    }

    const [salt, savedHashHex] = account.passwordHash.split(":");
    const savedHash = Buffer.from(savedHashHex, "hex");
    const enteredHash = crypto.scryptSync(password, salt, 64);

    const passwordMatches =
      savedHash.length === enteredHash.length &&
      crypto.timingSafeEqual(savedHash, enteredHash);

    if (!passwordMatches) {
      return res.status(401).send(
        messagePage("Sign-in details not recognized", "Check your email and password, then try again.")
      );
    }
const accountStatus = account.status || "active";

if (accountStatus !== "active") {
  const message = accountStatus === "pending"
    ? "Your application is waiting for review."
    : "This account is not currently active. Please contact NovaBank.";

  return res.status(403).send(
    messagePage("Account unavailable", message)
  );
}
    req.session.accountId = account.id;
    res.redirect("/dashboard.html");
  } catch (error) {
    console.error(error);
    res.status(500).send(
      messagePage("Something went wrong", "Please try again later.")
    );
  }
});
app.post("/admin/login", (req, res) => {
  const email = String(req.body.email || "").trim().toLowerCase();
  const password = String(req.body.password || "");

  const savedAdminEmail = String(process.env.ADMIN_EMAIL || "").trim().toLowerCase();
  const savedAdminPassword = String(process.env.ADMIN_PASSWORD || "");

  if (!savedAdminEmail || !savedAdminPassword) {
    return res.status(500).send(
      messagePage("Admin sign-in unavailable", "Check the admin settings in your .env file.")
    );
  }

  if (email !== savedAdminEmail || password !== savedAdminPassword) {
    return res.status(401).send(
      messagePage("Sign-in details not recognized", "Check your admin email and password, then try again.")
    );
  }

  req.session.isAdmin = true;
  res.redirect("/admin.html");
});
app.post("/admin/accounts/:id/status", async (req, res) => {
  if (!req.session.isAdmin) {
    return res.redirect("/admin-login.html");
  }

  const newStatus = String(req.body.status || "");

  if (!["active", "rejected", "suspended"].includes(newStatus)) {
    return res.status(400).send(
      messagePage("Invalid account status", "Choose a valid account action.")
    );
  }

  try {
    const accounts = await readAccounts();
    const account = accounts.find((item) => item.id === req.params.id);

    if (!account) {
      return res.status(404).send(
        messagePage("Customer not found", "That customer account could not be found.")
      );
    }

    account.status = newStatus;

    if (newStatus === "active" && !account.accountNumber) {
      account.accountNumber = createAccountNumber(accounts);
    }

    await fs.writeFile(accountsFile, JSON.stringify(accounts, null, 2), "utf8");
    res.redirect("/admin.html");
  } catch (error) {
    console.error(error);
    res.status(500).send(
      messagePage("Something went wrong", "Please try again later.")
    );
  }
});
app.get("/admin.html", async (req, res) => {
  if (!req.session.isAdmin) {
    return res.redirect("/admin-login.html");
  }

  try {
    const accounts = await readAccounts();

    const rows = accounts.length
      ? accounts.map((account) => {
          const accountType = String(account.accountType || "");
          const formattedType = accountType
            ? accountType.charAt(0).toUpperCase() + accountType.slice(1)
            : "—";
            const status = account.status || "active";
const statusAction = status === "active" ? "suspended" : "active";
const statusButton = status === "pending"
  ? "Approve"
  : status === "active"
    ? "Suspend"
    : "Reactivate";

const managementControls = status === "pending"
  ? `
      <form action="/admin/accounts/${encodeURIComponent(account.id)}/status" method="POST">
        <input type="hidden" name="status" value="active">
        <button type="submit">Approve</button>
      </form>
      <form action="/admin/accounts/${encodeURIComponent(account.id)}/status" method="POST">
        <input type="hidden" name="status" value="rejected">
        <button type="submit">Reject</button>
      </form>
    `
  : `
      <form action="/admin/accounts/${encodeURIComponent(account.id)}/status" method="POST">
        <input type="hidden" name="status" value="${statusAction}">
        <button type="submit">${statusButton}</button>
      </form>
    `;
          return `
            <tr>
              <td>${escapeHtml(account.fullName || "")}</td>
              <td>${escapeHtml(account.email || "")}</td>
              <td>${escapeHtml(formattedType)}</td>
              <td>${escapeHtml(account.accountNumber || "Not assigned")}</td>
              <td class="admin-status">${escapeHtml(account.status || "active")}</td>
              <td>${managementControls}</td>
            </tr>
          `;
        }).join("")
      : `<tr><td colspan="6">No customer accounts yet.</td></tr>`;
        const totalAccounts = accounts.length;
    const pendingAccounts = accounts.filter(
      (account) => account.status === "pending"
    ).length;
    const activeAccounts = accounts.filter(
      (account) => (account.status || "active") === "active"
    ).length;
    const suspendedAccounts = accounts.filter(
      (account) => account.status === "suspended"
    ).length;
    const adminFile = await fs.readFile(
      path.join(__dirname, "admin.html"),
      "utf8"
    );

    res.send(
  adminFile
    .replace("{{APPLICATION_ROWS}}", rows)
    .replace("{{TOTAL_ACCOUNTS}}", String(totalAccounts))
    .replace("{{PENDING_ACCOUNTS}}", String(pendingAccounts))
    .replace("{{ACTIVE_ACCOUNTS}}", String(activeAccounts))
    .replace("{{SUSPENDED_ACCOUNTS}}", String(suspendedAccounts))
);
  } catch (error) {
    console.error(error);
    res.status(500).send(
      messagePage("Something went wrong", "Please try again later.")
    );
  }
});
app.get("/dashboard.html", async (req, res) => {
  if (!req.session.accountId) {
    return res.redirect("/signin.html");
  }

  try {
    const accounts = await readAccounts();
    const account = accounts.find(
      (savedAccount) => savedAccount.id === req.session.accountId
    );

    if (!account) {
      return req.session.destroy(() => res.redirect("/signin.html"));
    }

    if (!account.accountNumber) {
      account.accountNumber = createAccountNumber(accounts);
      await fs.writeFile(accountsFile, JSON.stringify(accounts, null, 2), "utf8");
    }

    const accountType =
      account.accountType.charAt(0).toUpperCase() + account.accountType.slice(1);

    const dashboardFile = await fs.readFile(
      path.join(__dirname, "dashboard.html"),
      "utf8"
    );

    const dashboard = dashboardFile
      .replace("{{CUSTOMER_NAME}}", escapeHtml(account.fullName))
      .replace("{{ACCOUNT_TYPE}}", escapeHtml(accountType))
      .replace("{{ACCOUNT_NUMBER}}", escapeHtml(account.accountNumber));

    res.send(dashboard);
  } catch (error) {
    console.error(error);
    res.status(500).send(
      messagePage("Something went wrong", "Please try again later.")
    );
  }
});
app.post("/admin/logout", (req, res) => {
  req.session.destroy((error) => {
    if (error) {
      return res.status(500).send(
        messagePage("Something went wrong", "Please try again later.")
      );
    }

    res.clearCookie("connect.sid");
    res.redirect("/admin-login.html");
  });
});
app.post("/api/logout", (req, res) => {
  req.session.destroy((error) => {
    if (error) {
      return res.status(500).send(
        messagePage("Something went wrong", "Please try again later.")
      );
    }

    res.clearCookie("connect.sid");
    res.redirect("/signin.html");
  });
});

app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "index.html"));
});

app.get("/style.css", (req, res) => {
  res.sendFile(path.join(__dirname, "style.css"));
});

app.get("/:page", (req, res, next) => {
  if (!pages.includes(req.params.page)) {
    return next();
  }

  res.sendFile(path.join(__dirname, req.params.page));
});

app.use((req, res) => {
  res.status(404).send(messagePage("Page not found", "That page could not be found."));
});

app.listen(port, "127.0.0.1", () => {
  console.log(`NovaBank is running at http://localhost:${port}`);
});