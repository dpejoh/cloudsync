import { normalizeServerUrl } from "../src/misc";

describe("normalizeServerUrl", () => {
  it("assumes https for a bare host", () => {
    expect(normalizeServerUrl("cloudsync.8411235.workers.dev")).toBe(
      "https://cloudsync.8411235.workers.dev"
    );
    expect(normalizeServerUrl("  sync.example.com  ")).toBe("https://sync.example.com");
  });

  it("keeps an explicit scheme and strips trailing slashes", () => {
    expect(normalizeServerUrl("https://sync.example.com/")).toBe("https://sync.example.com");
    expect(normalizeServerUrl("http://sync.example.com:3000///")).toBe(
      "http://sync.example.com:3000"
    );
    expect(normalizeServerUrl("https://sync.example.com/base")).toBe(
      "https://sync.example.com/base"
    );
  });

  it("assumes http only for local addresses", () => {
    expect(normalizeServerUrl("localhost:3901")).toBe("http://localhost:3901");
    expect(normalizeServerUrl("127.0.0.1:3901")).toBe("http://127.0.0.1:3901");
    expect(normalizeServerUrl("localhost")).toBe("http://localhost");
  });

  it("rejects invalid or unsupported input", () => {
    expect(normalizeServerUrl("")).toBeNull();
    expect(normalizeServerUrl("   ")).toBeNull();
    expect(normalizeServerUrl("ftp://sync.example.com")).toBeNull();
    expect(normalizeServerUrl("https://")).toBeNull();
    expect(normalizeServerUrl("not a url")).toBeNull();
  });
});
