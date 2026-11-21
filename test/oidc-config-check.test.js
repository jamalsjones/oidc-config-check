const test = require("node:test");
const assert = require("node:assert");
const fs = require("node:fs");
const path = require("node:path");
const { execFileSync } = require("node:child_process");
const { check, wellKnownUrl } = require("../oidc-config-check.js");

const load = (n) => JSON.parse(fs.readFileSync(path.join(__dirname, "..", "examples", n), "utf8"));
const ids = (r) => r.findings.map((f) => f.id);

test("the modern example has no errors or warnings", () => {
  const r = check(load("modern.json"), { sourceUrl: "https://login.example.com/.well-known/openid-configuration" });
  assert.strictEqual(r.summary.error, 0, JSON.stringify(r.findings));
  assert.strictEqual(r.summary.warn, 0, JSON.stringify(r.findings));
});

test("the legacy example catches each weakness", () => {
  const got = ids(check(load("legacy.json")));
  for (const id of ["alg-none", "pkce-no-s256", "pkce-plain", "implicit", "hybrid-token", "grant-implicit", "grant-password", "userinfo_endpoint-http", "some-hs", "auth-secrets-only"]) {
    assert.ok(got.includes(id), "expected " + id);
  }
});

test("missing required fields", () => {
  const r = check({ issuer: "https://a.example.com" });
  for (const f of ["authorization_endpoint", "jwks_uri", "response_types_supported", "subject_types_supported", "id_token_signing_alg_values_supported"]) {
    assert.ok(ids(r).includes("missing-" + f));
  }
});

test("issuer rules", () => {
  assert.ok(ids(check({ ...load("modern.json"), issuer: "http://login.example.com" })).includes("issuer-http"));
  assert.ok(ids(check({ ...load("modern.json"), issuer: "https://login.example.com?x=1" })).includes("issuer-query"));
  const src = { sourceUrl: "https://login.example.com/.well-known/openid-configuration" };
  assert.ok(ids(check({ ...load("modern.json"), issuer: "https://evil.example.net" }, src)).includes("issuer-mismatch"));
  assert.ok(ids(check({ ...load("modern.json"), issuer: "https://login.example.com/" }, src)).includes("issuer-slash"));
});

test("no PKCE listed warns", () => {
  const { code_challenge_methods_supported, ...rest } = load("modern.json");
  assert.ok(ids(check(rest)).includes("pkce-unknown"));
});

test("only HS algorithms and missing RS256", () => {
  const r = check({ ...load("modern.json"), id_token_signing_alg_values_supported: ["HS256"] });
  assert.ok(ids(r).includes("only-hs"));
  assert.ok(ids(r).includes("no-rs256"));
});

test("invalid JSON", () => {
  assert.ok(ids(check("{nope")).includes("json"));
  assert.ok(ids(check("[]")).includes("json"));
});

test("wellKnownUrl", () => {
  assert.strictEqual(wellKnownUrl("login.example.com"), "https://login.example.com/.well-known/openid-configuration");
  assert.strictEqual(wellKnownUrl("https://login.example.com/tenant/"), "https://login.example.com/tenant/.well-known/openid-configuration");
  assert.strictEqual(wellKnownUrl("https://x.example.com/.well-known/openid-configuration"), "https://x.example.com/.well-known/openid-configuration");
});

test("CLI reads a file and sets the exit code", () => {
  const bin = path.join(__dirname, "..", "oidc-config-check.js");
  const ex = (n) => path.join(__dirname, "..", "examples", n);
  assert.match(execFileSync("node", [bin, ex("modern.json")]).toString(), /0 errors, 0 warnings/);
  assert.throws(() => execFileSync("node", [bin, ex("legacy.json")], { stdio: "pipe" }), (e) => e.status === 1);
});
