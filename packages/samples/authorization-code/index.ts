import "dotenv/config";
import { createCliAuth, memoryStorage } from "cli-auth";
import { spawn } from "node:child_process";
import { readFile } from "node:fs/promises";

const storage = memoryStorage();

const template = await readFile(
  new URL("./callback.html", import.meta.url),
  "utf-8"
);

function escapeHtml(input: string): string {
  return input
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

function renderPage(vars: {
  variant: "success" | "error" | "warn";
  icon: string;
  title: string;
  message: string;
  detail?: string;
}): string {
  const replacements: Record<string, string> = {
    variant: vars.variant,
    icon: vars.icon,
    title: escapeHtml(vars.title),
    message: escapeHtml(vars.message),
    detail: vars.detail ? `<code>${escapeHtml(vars.detail)}</code>` : "",
  };
  return template.replace(/\{\{(\w+)\}\}/g, (_, key) => replacements[key] ?? "");
}

const auth = createCliAuth({
  strategy: "authorization-code",
  provider: {
    metadata: {
      authorizationEndpoint: process.env.AUTH_CODE_AUTHORIZATION_ENDPOINT!,
      tokenEndpoint: process.env.AUTH_CODE_TOKEN_ENDPOINT!,
    },
  },
  clientId: process.env.AUTH_CODE_CLIENT_ID!,
  storage,
  scope: process.env.AUTH_CODE_SCOPE,
  extraParams: { prompt: "consent" },
  callbackSource: (res, { success, callbackUrl, verifyError }) => {
    res.writeHead(success ? 200 : 400, {
      "Content-Type": "text/html; charset=utf-8",
    });

    if (success) {
      res.end(
        renderPage({
          variant: "success",
          icon: "✓",
          title: "You're signed in",
          message: "Authorization successful. The CLI has received your credentials.",
        })
      );
      return;
    }

    if (verifyError === "state_mismatch") {
      res.end(
        renderPage({
          variant: "warn",
          icon: "!",
          title: "Link expired or tampered",
          message:
            "The callback state did not match. This link may have been opened twice or intercepted. Please try signing in again from your terminal.",
        })
      );
      return;
    }

    if (verifyError === "missing_code") {
      res.end(
        renderPage({
          variant: "warn",
          icon: "?",
          title: "Malformed callback",
          message: "The authorization server did not return a code. Please try again.",
        })
      );
      return;
    }

    const error = callbackUrl.searchParams.get("error") ?? "unknown_error";
    const description = callbackUrl.searchParams.get("error_description");
    res.end(
      renderPage({
        variant: "error",
        icon: "✕",
        title: "Authorization failed",
        message: description ?? "The authorization server returned an error.",
        detail: error,
      })
    );
  },
});

console.log("Starting login...");
try {
  await auth.login({
    onAuthorization: (url) => {
      console.log("\nOpening browser for authorization...");
      console.log("URL:", url);
      spawn("open", [url], { detached: true, stdio: "ignore" }).unref();
    },
  });
} catch (error) {
  console.error("\nLogin failed:", error instanceof Error ? error.message : error);
  process.exit(1);
}

console.log("\nStored token set:", JSON.stringify(await storage.load(), null, 2));

const status = await auth.status();
console.log("\nStatus:", status);

const token = await auth.getToken();
console.log("Access token:", token);

console.log("\nLogging out...");
await auth.logout();

const statusAfter = await auth.status();
console.log("Status after logout:", statusAfter);
