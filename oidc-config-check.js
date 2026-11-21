#!/usr/bin/env node
/*
 * oidc-config-check: reviews an OpenID Connect discovery document
 * (/.well-known/openid-configuration) against OpenID Connect Discovery 1.0,
 * the OAuth 2.0 Security Best Current Practice (RFC 9700) and RFC 8725.
 *
 * One file, no dependencies. It works three ways:
 *   - in a browser, as a plain <script> (it sets window.OidcConfigCheck)
 *   - in Node, as a module: const { check } = require("./oidc-config-check.js")
 *   - in Node, as a command: node oidc-config-check.js <issuer-url | file.json>
 *
 * A discovery document says what a provider offers, not how each client is
 * set up. A provider that still offers the implicit flow is worth fixing even
 * if none of your apps use it, because any client registered later can.
 *
 * MIT License. https://github.com/jamalsjones/oidc-config-check
 */
(function (root, factory) {
  if (typeof module === "object" && module.exports) module.exports = factory();
  else root.OidcConfigCheck = factory();
})(typeof self !== "undefined" ? self : this, function () {
  "use strict";

  var DISC = "OpenID Connect Discovery 1.0";
  var BCP = "RFC 9700";

  var REQUIRED = [
    "issuer",
    "authorization_endpoint",
    "jwks_uri",
    "response_types_supported",
    "subject_types_supported",
    "id_token_signing_alg_values_supported",
  ];

  var ENDPOINTS = [
    "authorization_endpoint",
    "token_endpoint",
    "userinfo_endpoint",
    "jwks_uri",
    "registration_endpoint",
    "end_session_endpoint",
    "revocation_endpoint",
    "introspection_endpoint",
    "pushed_authorization_request_endpoint",
    "device_authorization_endpoint",
    "backchannel_authentication_endpoint",
    "check_session_iframe",
  ];

  function wellKnownUrl(input) {
    var u = String(input || "").trim();
    if (!u) return null;
    if (!/^https?:\/\//i.test(u)) u = "https://" + u;
    if (/\/\.well-known\/openid-configuration\/?$/.test(u)) return u.replace(/\/$/, "");
    return u.replace(/\/+$/, "") + "/.well-known/openid-configuration";
  }

  function issuerFromUrl(url) {
    return String(url).replace(/\/\.well-known\/openid-configuration\/?$/, "");
  }

  function parseUrl(v) {
    try {
      return new URL(v);
    } catch (e) {
      return null;
    }
  }

  function list(v) {
    return Array.isArray(v) ? v : null;
  }

  function check(config, options) {
    options = options || {};
    var findings = [];
    function add(level, id, field, message, ref) {
      findings.push({ level: level, id: id, field: field, message: message, ref: ref || null });
    }
    var result = { findings: findings, summary: null, config: null };

    var c = config;
    if (typeof c === "string") {
      try {
        c = JSON.parse(c);
      } catch (e) {
        add("error", "json", null, "This isn't valid JSON: " + e.message);
        return finish(result);
      }
    }
    if (!c || typeof c !== "object" || Array.isArray(c)) {
      add("error", "json", null, "A discovery document is a JSON object.");
      return finish(result);
    }
    result.config = c;

    // ---- Required fields and the issuer -----------------------------------

    REQUIRED.forEach(function (f) {
      if (c[f] === undefined) add("error", "missing-" + f, f, f + " is missing. Discovery requires it.", DISC + " §3");
    });
    var codeFlow = (list(c.response_types_supported) || []).some(function (t) {
      return /\bcode\b/.test(t);
    });
    if (c.token_endpoint === undefined && codeFlow) {
      add("error", "missing-token_endpoint", "token_endpoint", "token_endpoint is missing, but the code flow is offered and needs it.", DISC + " §3");
    }

    var iss = parseUrl(c.issuer);
    if (c.issuer !== undefined) {
      if (!iss) {
        add("error", "issuer-invalid", "issuer", "issuer isn't a valid URL.", DISC + " §3");
      } else {
        if (iss.protocol !== "https:") add("error", "issuer-http", "issuer", "issuer must use https.", DISC + " §3");
        if (iss.search || iss.hash) add("error", "issuer-query", "issuer", "issuer must not have a query or fragment.", DISC + " §3");
      }
    }
    if (options.sourceUrl && typeof c.issuer === "string") {
      var expected = issuerFromUrl(options.sourceUrl);
      if (c.issuer !== expected && c.issuer.replace(/\/$/, "") !== expected.replace(/\/$/, "")) {
        add("error", "issuer-mismatch", "issuer", "This document was fetched from " + expected + " but says its issuer is " + c.issuer + ". Clients must reject a mismatch; it's how one provider impersonates another.", DISC + " §4.3");
      } else if (c.issuer !== expected) {
        add("warn", "issuer-slash", "issuer", "The issuer and the URL it was fetched from differ only by a trailing slash. Clients compare issuers exactly, so some will reject tokens over this.", DISC + " §4.3");
      }
    }

    // ---- Endpoints ---------------------------------------------------------

    var otherHosts = {};
    ENDPOINTS.forEach(function (f) {
      if (c[f] === undefined) return;
      var u = parseUrl(c[f]);
      if (!u) {
        add("error", f + "-invalid", f, f + " isn't a valid URL.", DISC + " §3");
        return;
      }
      if (u.protocol !== "https:" && u.hostname !== "localhost" && u.hostname !== "127.0.0.1") {
        add("error", f + "-http", f, f + " uses " + u.protocol.replace(":", "") + ". Codes, tokens and keys must travel over TLS.", BCP + " §2.6; " + DISC + " §3");
      }
      if (iss && u.host !== iss.host) {
        (otherHosts[u.host] = otherHosts[u.host] || []).push(f);
      }
    });
    var hostNames = Object.keys(otherHosts);
    if (hostNames.length) {
      add("info", "other-hosts", null, "Some endpoints aren't on the issuer's host (" + iss.host + "): " + hostNames.map(function (h) {
        return h + " (" + otherHosts[h].join(", ") + ")";
      }).join("; ") + ". That's common, but confirm each host is yours.", null);
    }

    // ---- Flows -------------------------------------------------------------

    var rts = list(c.response_types_supported);
    if (c.response_types_supported !== undefined && !rts) {
      add("error", "response_types-type", "response_types_supported", "response_types_supported should be a list.", DISC + " §3");
    }
    if (rts) {
      var implicit = rts.filter(function (t) {
        var parts = String(t).split(/\s+/);
        return parts.indexOf("code") === -1 && (parts.indexOf("token") !== -1 || parts.indexOf("id_token") !== -1);
      });
      if (implicit.length) {
        add("warn", "implicit", "response_types_supported", "The implicit flow is offered (" + implicit.join(", ") + "). It puts tokens in the browser's URL, where they leak to history, logs and referrers. Use the code flow with PKCE and turn implicit off.", BCP + " §2.1.2");
      }
      var hybridToken = rts.filter(function (t) {
        var parts = String(t).split(/\s+/);
        return parts.indexOf("code") !== -1 && parts.indexOf("token") !== -1;
      });
      if (hybridToken.length) {
        add("warn", "hybrid-token", "response_types_supported", "A hybrid flow that returns an access token from the authorization endpoint is offered (" + hybridToken.join(", ") + "). Access tokens shouldn't come back in the front channel.", BCP + " §2.1.2");
      }
      if (rts.indexOf("code") === -1) {
        add("warn", "no-code", "response_types_supported", "The plain code flow isn't listed. It's the flow every client should use.", BCP + " §2.1.1");
      }
    }

    var grants = list(c.grant_types_supported);
    if (grants) {
      if (grants.indexOf("implicit") !== -1) {
        add("warn", "grant-implicit", "grant_types_supported", "The implicit grant is listed.", BCP + " §2.1.2");
      }
      if (grants.indexOf("password") !== -1) {
        add("warn", "grant-password", "grant_types_supported", "The password grant is listed. It hands the user's password to the client, and it can't do MFA or federation. RFC 9700 says it must not be used.", BCP + " §2.4");
      }
    } else if (c.grant_types_supported === undefined && rts) {
      add("info", "grant-default", "grant_types_supported", "grant_types_supported isn't listed, which means \"authorization_code and implicit\" by default. Listing it makes clear what's really allowed.", DISC + " §3");
    }

    var pkce = list(c.code_challenge_methods_supported);
    if (!pkce) {
      add("warn", "pkce-unknown", "code_challenge_methods_supported", "code_challenge_methods_supported isn't listed, so clients can't tell whether PKCE is supported. Every client should use PKCE with S256.", BCP + " §2.1.1; RFC 8414 §2");
    } else {
      if (pkce.indexOf("S256") === -1) {
        add("error", "pkce-no-s256", "code_challenge_methods_supported", "PKCE is listed without S256. The plain method sends the verifier in the clear, which is the thing PKCE exists to avoid.", BCP + " §2.1.1; RFC 7636 §4.2");
      }
      if (pkce.indexOf("plain") !== -1) {
        add("warn", "pkce-plain", "code_challenge_methods_supported", "PKCE \"plain\" is offered. Clients should use S256, and the provider shouldn't accept plain.", BCP + " §2.1.1");
      }
    }

    // ---- Signing -----------------------------------------------------------

    var algs = list(c.id_token_signing_alg_values_supported);
    if (algs) {
      if (
        algs.some(function (a) {
          return String(a).toLowerCase() === "none";
        })
      ) {
        add("error", "alg-none", "id_token_signing_alg_values_supported", "\"none\" is an accepted ID token algorithm. That means unsigned ID tokens. Turn it off.", "RFC 8725 §3.1; " + DISC + " §3");
      }
      if (algs.indexOf("RS256") === -1) {
        add("warn", "no-rs256", "id_token_signing_alg_values_supported", "RS256 isn't listed. Discovery says it must be, and many client libraries expect it.", DISC + " §3");
      }
      var symmetric = algs.filter(function (a) {
        return /^HS/.test(a);
      });
      if (symmetric.length && symmetric.length === algs.length) {
        add("warn", "only-hs", "id_token_signing_alg_values_supported", "Only shared-secret algorithms (" + symmetric.join(", ") + ") are offered. Any client that can check an ID token can also forge one.", "RFC 8725 §3.5");
      } else if (symmetric.length) {
        add("info", "some-hs", "id_token_signing_alg_values_supported", "Shared-secret algorithms (" + symmetric.join(", ") + ") are offered alongside asymmetric ones. Make sure clients pin the one they expect, so a token can't switch algorithms.", "RFC 8725 §3.1");
      }
    }
    [
      "userinfo_signing_alg_values_supported",
      "request_object_signing_alg_values_supported",
      "token_endpoint_auth_signing_alg_values_supported",
      "introspection_signing_alg_values_supported",
      "authorization_signing_alg_values_supported",
    ].forEach(function (f) {
      var v = list(c[f]);
      if (
        v &&
        v.some(function (a) {
          return String(a).toLowerCase() === "none";
        })
      ) {
        add(f === "token_endpoint_auth_signing_alg_values_supported" ? "error" : "warn", f + "-none", f, f + " includes \"none\".", "RFC 8725 §3.1");
      }
    });

    // ---- Client authentication ---------------------------------------------

    var auth = list(c.token_endpoint_auth_methods_supported);
    if (auth) {
      var strong = auth.filter(function (m) {
        return ["private_key_jwt", "tls_client_auth", "self_signed_tls_client_auth"].indexOf(m) !== -1;
      });
      if (!strong.length) {
        add("info", "auth-secrets-only", "token_endpoint_auth_methods_supported", "Confidential clients can only use shared secrets (" + auth.join(", ") + "). private_key_jwt or mTLS keep a secret from being copied out of a config file.", BCP + " §2.5");
      }
      if (auth.indexOf("client_secret_jwt") !== -1) {
        add("info", "auth-secret-jwt", "token_endpoint_auth_methods_supported", "client_secret_jwt is offered. It's still a shared secret; prefer private_key_jwt.", BCP + " §2.5");
      }
    } else if (c.token_endpoint) {
      add("info", "auth-default", "token_endpoint_auth_methods_supported", "token_endpoint_auth_methods_supported isn't listed, which means client_secret_basic only.", DISC + " §3");
    }

    // ---- Request handling and newer defenses -------------------------------

    if (c.request_uri_parameter_supported !== false && c.require_request_uri_registration !== true && (c.request_uri_parameter_supported === true || c.request_uri_parameter_supported === undefined)) {
      add("info", "request-uri", "request_uri_parameter_supported", "request_uri is " + (c.request_uri_parameter_supported === undefined ? "supported by default" : "supported") + " without requiring registered URIs. The provider will fetch a URL the client names, which is a server-side request forgery risk unless it's restricted.", "OpenID Connect Core §6.2; " + BCP + " §4.5.3");
    }
    if (c.authorization_response_iss_parameter_supported !== true) {
      add("info", "no-iss-param", "authorization_response_iss_parameter_supported", "The provider doesn't say it returns iss in authorization responses. That's the simplest defense against mix-up attacks when a client uses more than one provider.", "RFC 9207; " + BCP + " §4.4");
    }
    if (c.pushed_authorization_request_endpoint === undefined) {
      add("info", "no-par", "pushed_authorization_request_endpoint", "No pushed authorization requests (PAR). PAR keeps request parameters out of the browser and stops them being tampered with.", "RFC 9126");
    }
    if (c.dpop_signing_alg_values_supported === undefined && c.tls_client_certificate_bound_access_tokens !== true) {
      add("info", "no-sender-constraint", null, "There's no sign of sender-constrained tokens (DPoP or mTLS). Without them, a stolen access token works for whoever holds it.", BCP + " §2.2.1; RFC 9449; RFC 8705");
    }
    if (c.end_session_endpoint === undefined) {
      add("info", "no-logout", "end_session_endpoint", "No end_session_endpoint, so apps can't end the user's session at the provider when they sign out.", "OpenID Connect RP-Initiated Logout 1.0");
    }
    if (c.revocation_endpoint === undefined) {
      add("info", "no-revocation", "revocation_endpoint", "No revocation_endpoint is advertised, so clients can't revoke tokens when a user signs out or a device is lost.", "RFC 7009");
    }

    var scopes = list(c.scopes_supported);
    if (scopes && scopes.indexOf("openid") === -1) {
      add("warn", "no-openid-scope", "scopes_supported", "scopes_supported doesn't include openid. Discovery says the provider must support it.", DISC + " §3");
    }
    var modes = list(c.response_modes_supported);
    if (modes && modes.indexOf("fragment") !== -1 && rts && implicit && implicit.length) {
      add("info", "fragment", "response_modes_supported", "The fragment response mode is offered, which is how implicit tokens reach the browser.", BCP + " §2.1.2");
    }
    if (c.registration_endpoint !== undefined) {
      add("info", "open-registration", "registration_endpoint", "Dynamic client registration is advertised. If it's open, anyone can register a client. Check it needs an initial access token.", "RFC 7591 §3");
    }

    return finish(result);
  }

  var ORDER = { error: 0, warn: 1, info: 2 };
  function finish(result) {
    result.findings.sort(function (a, b) {
      return ORDER[a.level] - ORDER[b.level];
    });
    var s = { error: 0, warn: 0, info: 0 };
    result.findings.forEach(function (f) {
      s[f.level]++;
    });
    s.pass = s.error === 0;
    result.summary = s;
    return result;
  }

  // ---- Command line ---------------------------------------------------------

  function cli(argv) {
    var args = argv.slice(2);
    var json = false;
    var failOn = "error";
    var target = null;
    for (var i = 0; i < args.length; i++) {
      var a = args[i];
      if (a === "--json") json = true;
      else if (a === "--fail-on") failOn = args[++i];
      else if (a === "-h" || a === "--help") return help();
      else if (a[0] === "-" && a !== "-") {
        process.stderr.write("Unknown option " + a + "\n");
        process.exit(2);
      } else target = a;
    }

    function report(r) {
      if (json) process.stdout.write(JSON.stringify({ findings: r.findings, summary: r.summary }, null, 2) + "\n");
      else {
        r.findings.forEach(function (f) {
          var tag = f.level === "error" ? "ERROR" : f.level === "warn" ? "WARN " : "INFO ";
          process.stdout.write(tag + "  " + (f.field ? "[" + f.field + "] " : "") + f.message + (f.ref ? "  (" + f.ref + ")" : "") + "\n");
        });
        process.stdout.write((r.findings.length ? "\n" : "") + r.summary.error + " errors, " + r.summary.warn + " warnings, " + r.summary.info + " notes.\n");
      }
      process.exit(r.summary.error > 0 || (failOn === "warn" && r.summary.warn > 0) ? 1 : 0);
    }

    if (!target && process.stdin.isTTY) return help();
    if (!target || target === "-") {
      var buf = "";
      process.stdin.setEncoding("utf8");
      process.stdin.on("data", function (d) {
        buf += d;
      });
      process.stdin.on("end", function () {
        report(check(buf));
      });
      return;
    }
    var fs = require("fs");
    if (fs.existsSync(target)) return report(check(fs.readFileSync(target, "utf8")));
    var url = wellKnownUrl(target);
    fetch(url, { headers: { accept: "application/json" } })
      .then(function (res) {
        if (!res.ok) throw new Error("HTTP " + res.status + " from " + url);
        return res.text();
      })
      .then(function (text) {
        report(check(text, { sourceUrl: url }));
      })
      .catch(function (e) {
        process.stderr.write("Couldn't fetch " + url + ": " + e.message + "\n");
        process.exit(2);
      });
  }

  function help() {
    process.stdout.write(
      [
        "Usage: node oidc-config-check.js <issuer-url | discovery.json> [options]",
        "       curl -s $ISSUER/.well-known/openid-configuration | node oidc-config-check.js",
        "",
        "Reviews an OpenID Connect discovery document.",
        "Exits 1 if any errors are found (or warnings, with --fail-on warn).",
        "",
        "  --fail-on warn   also fail on warnings",
        "  --json           print the findings as JSON",
        "",
      ].join("\n")
    );
  }

  if (typeof require !== "undefined" && typeof module !== "undefined" && require.main === module) {
    cli(process.argv);
  }

  return { check: check, wellKnownUrl: wellKnownUrl, cli: cli };
});
