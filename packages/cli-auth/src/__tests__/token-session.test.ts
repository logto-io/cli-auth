import { describe, it, expect } from "vitest";
import { resolveSession } from "../token-manager.js";
import type { TokenSet } from "../types.js";

describe("resolveSession", () => {
  it("returns empty when storage is undefined", () => {
    expect(resolveSession(undefined, "")).toEqual({ type: "empty" });
  });

  it("returns empty when storage has no tokens and no refresh_token", () => {
    const stored: TokenSet = { tokens: {} };
    expect(resolveSession(stored, "")).toEqual({ type: "empty" });
  });

  it("returns empty when storage has tokens but not for the requested key and no refresh_token", () => {
    const stored: TokenSet = {
      tokens: {
        "resource=https://other.com": {
          access_token: "other",
          expires_at: 9_999_999,
        },
      },
    };
    expect(resolveSession(stored, "resource=https://api.com")).toEqual({ type: "empty" });
  });

  it("returns refresh-only when storage has refresh_token but no token for the requested key", () => {
    const stored: TokenSet = {
      refresh_token: "rt-1",
      tokens: {},
    };
    expect(resolveSession(stored, "")).toEqual({
      type: "refresh-only",
      refreshToken: "rt-1",
    });
  });

  it("returns active when storage has a token for the requested key", () => {
    const cached = { access_token: "at-1", expires_at: 9_999_999, scope: "openid" };
    const stored: TokenSet = {
      tokens: { "": cached },
    };
    expect(resolveSession(stored, "")).toEqual({
      type: "active",
      cached,
    });
  });

  it("returns active (not refresh-only) when both cached token and refresh_token exist", () => {
    const cached = { access_token: "at-1", expires_at: 9_999_999 };
    const stored: TokenSet = {
      refresh_token: "rt-1",
      tokens: { "": cached },
    };
    const session = resolveSession(stored, "");
    expect(session.type).toBe("active");
  });

  it("returns refresh-only for a specific key even when other keys have tokens", () => {
    const stored: TokenSet = {
      refresh_token: "rt-1",
      tokens: {
        "": { access_token: "default", expires_at: 9_999_999 },
      },
    };
    expect(resolveSession(stored, "resource=https://api.com")).toEqual({
      type: "refresh-only",
      refreshToken: "rt-1",
    });
  });
});
