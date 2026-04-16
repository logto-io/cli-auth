import { describe, it, expect, vi } from "vitest";
import { buildTokenCacheKey, fetchTokenResponse, refreshTokenGrant, revokeToken } from "../utils.js";

describe("buildTokenCacheKey", () => {
  it("returns empty string when no options", () => {
    expect(buildTokenCacheKey()).toBe("");
    expect(buildTokenCacheKey({})).toBe("");
  });

  it("returns resource-based key", () => {
    expect(buildTokenCacheKey({ resource: "https://api.example.com" })).toBe(
      "resource=https://api.example.com"
    );
  });

  it("returns sorted extraParams key", () => {
    expect(
      buildTokenCacheKey({ extraParams: { z_param: "z", a_param: "a" } })
    ).toBe("a_param=a&z_param=z");
  });

  it("returns combined key with resource first then sorted extraParams", () => {
    expect(
      buildTokenCacheKey({
        resource: "https://api.example.com",
        extraParams: { organization_id: "org_1" },
      })
    ).toBe("resource=https://api.example.com&organization_id=org_1");
  });

  it("produces consistent keys regardless of extraParams insertion order", () => {
    const key1 = buildTokenCacheKey({
      extraParams: { b: "2", a: "1", c: "3" },
    });
    const key2 = buildTokenCacheKey({
      extraParams: { c: "3", a: "1", b: "2" },
    });
    expect(key1).toBe(key2);
  });
});

describe("fetchTokenResponse", () => {
  it("uses provided fetch function to make the request", async () => {
    const fakeFetch = vi.fn<typeof fetch>().mockResolvedValue(
      Response.json({
        access_token: "custom-token",
        token_type: "Bearer",
        expires_in: 3600,
      })
    );

    const result = await fetchTokenResponse({
      endpoint: "https://auth.example.com/token",
      body: new URLSearchParams({ grant_type: "client_credentials" }),
      fetch: fakeFetch,
    });

    expect(result.access_token).toBe("custom-token");
    expect(fakeFetch).toHaveBeenCalledOnce();
  });
});

describe("revokeToken", () => {
  it("throws on non-2xx response", async () => {
    const fakeFetch = vi.fn<typeof fetch>().mockResolvedValue(
      new Response(null, { status: 503 })
    );

    await expect(
      revokeToken({
        endpoint: "https://auth.example.com/revoke",
        clientId: "my-client",
        token: "bad-token",
        fetch: fakeFetch,
      })
    ).rejects.toThrow("Token revocation failed with status 503");
  });

  it("uses provided fetch function", async () => {
    const fakeFetch = vi.fn<typeof fetch>().mockResolvedValue(
      new Response(null, { status: 200 })
    );

    await revokeToken({
      endpoint: "https://auth.example.com/revoke",
      clientId: "c",
      token: "t",
      fetch: fakeFetch,
    });

    expect(fakeFetch).toHaveBeenCalledOnce();
  });

  it("sends POST with client_id and token as form-urlencoded", async () => {
    const fakeFetch = vi.fn<typeof fetch>().mockResolvedValue(
      new Response(null, { status: 200 })
    );

    await revokeToken({
      endpoint: "https://auth.example.com/revoke",
      clientId: "my-client",
      token: "refresh-token-1",
      fetch: fakeFetch,
    });

    expect(fakeFetch).toHaveBeenCalledOnce();
    const [url, init] = fakeFetch.mock.calls[0]!;
    expect(url).toBe("https://auth.example.com/revoke");
    expect(init?.method).toBe("POST");
    expect(init?.headers).toEqual(
      expect.objectContaining({ "Content-Type": "application/x-www-form-urlencoded" })
    );
    const body = new URLSearchParams(init?.body as string);
    expect(body.get("client_id")).toBe("my-client");
    expect(body.get("token")).toBe("refresh-token-1");
  });
});

describe("refreshTokenGrant", () => {
  it("uses provided fetch function for the token request", async () => {
    const fakeFetch = vi.fn<typeof fetch>().mockResolvedValue(
      Response.json({
        access_token: "refreshed-token",
        token_type: "Bearer",
        expires_in: 3600,
      })
    );

    const result = await refreshTokenGrant({
      tokenEndpoint: "https://auth.example.com/token",
      clientId: "my-client",
      refreshToken: "my-refresh-token",
      fetch: fakeFetch,
    });

    expect(result.access_token).toBe("refreshed-token");
    expect(fakeFetch).toHaveBeenCalledOnce();
  });
});
