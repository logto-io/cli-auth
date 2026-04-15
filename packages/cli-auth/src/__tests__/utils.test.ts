import { describe, it, expect } from "vitest";
import { buildTokenCacheKey } from "../utils.js";

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
