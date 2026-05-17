import { describe, expect, it } from "vitest";
import { isEmailAllowed } from "../src/allowlist/check.js";

describe("isEmailAllowed", () => {
  it("returns false for empty patterns (fail closed)", () => {
    expect(isEmailAllowed("peter@techimpossible.com", [])).toBe(false);
  });

  it("matches exact emails case-insensitively", () => {
    expect(isEmailAllowed("Peter@TechImpossible.com", ["peter@techimpossible.com"])).toBe(true);
  });

  it("matches *@domain wildcard case-insensitively", () => {
    expect(isEmailAllowed("anyone@TechImpossible.com", ["*@techimpossible.com"])).toBe(true);
  });

  it("rejects unrelated domain for *@domain wildcard", () => {
    expect(isEmailAllowed("anyone@gmail.com", ["*@techimpossible.com"])).toBe(false);
  });

  it("rejects email that is a substring of an allowed domain", () => {
    expect(isEmailAllowed("eve@evil-techimpossible.com", ["*@techimpossible.com"])).toBe(false);
  });

  it("supports mixed exact + wildcard patterns", () => {
    const patterns = ["*@techimpossible.com", "client@external.example"];
    expect(isEmailAllowed("client@external.example", patterns)).toBe(true);
    expect(isEmailAllowed("other@external.example", patterns)).toBe(false);
    expect(isEmailAllowed("peter@techimpossible.com", patterns)).toBe(true);
  });

  it("ignores malformed patterns silently", () => {
    expect(isEmailAllowed("peter@techimpossible.com", ["", "*@"])).toBe(false);
  });

  it("returns false for empty email", () => {
    expect(isEmailAllowed("", ["*@techimpossible.com"])).toBe(false);
  });

  it("trims surrounding whitespace from patterns", () => {
    expect(isEmailAllowed("peter@techimpossible.com", ["  *@techimpossible.com  "])).toBe(true);
  });
});
