import { describe, it, expect } from "vitest";
import { createCliAuth } from "../index.js";

describe("static-token", () => {
  it("getToken returns the token as-is without login", async () => {
    const auth = createCliAuth({
      strategy: "static-token",
      token: "my-ci-token",
    });

    const token = await auth.getToken();
    expect(token).toBe("my-ci-token");
  });

  it("status shows authenticated with method static-token", async () => {
    const auth = createCliAuth({
      strategy: "static-token",
      token: "my-ci-token",
    });

    const status = await auth.status();
    expect(status).toEqual({
      authenticated: true,
      strategy: "static-token",
    });
  });
});
