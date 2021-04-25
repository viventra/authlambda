"use strict";
// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.MissingRequiredGroupError = exports.validateAndCheckIdToken = exports.timestampInSeconds = exports.sign = exports.urlSafe = exports.createErrorHtml = exports.httpPostWithRetry = exports.decodeToken = exports.generateCookieHeaders = exports.extractAndParseCookies = exports.getElasticsearchCookieNames = exports.getAmplifyCookieNames = exports.asCloudFrontHeaders = exports.getCompleteConfig = exports.getConfig = void 0;
const fs_1 = require("fs");
const crypto_1 = require("crypto");
const cookie_1 = require("cookie");
const axios_1 = __importDefault(require("axios"));
const https_1 = require("https");
const template_html_1 = __importDefault(require("./error-page/template.html"));
const validate_jwt_1 = require("./validate-jwt");
function getDefaultCookieSettings(props) {
    // Defaults can be overridden by the user (CloudFormation Stack parameter) but should be solid enough for most purposes
    if (props.compatibility === "amplify") {
        if (props.mode === "spaMode") {
            return {
                idToken: "Path=/; Secure; SameSite=Lax",
                accessToken: "Path=/; Secure; SameSite=Lax",
                refreshToken: "Path=/; Secure; SameSite=Lax",
                nonce: "Path=/; Secure; HttpOnly; SameSite=Lax",
            };
        }
        else if (props.mode === "staticSiteMode") {
            return {
                idToken: "Path=/; Secure; HttpOnly; SameSite=Lax",
                accessToken: "Path=/; Secure; HttpOnly; SameSite=Lax",
                refreshToken: "Path=/; Secure; HttpOnly; SameSite=Lax",
                nonce: "Path=/; Secure; HttpOnly; SameSite=Lax",
            };
        }
    }
    else if (props.compatibility === "elasticsearch") {
        return {
            idToken: "Path=/; Secure; HttpOnly; SameSite=Lax",
            accessToken: "Path=/; Secure; HttpOnly; SameSite=Lax",
            refreshToken: "Path=/; Secure; HttpOnly; SameSite=Lax",
            nonce: "Path=/; Secure; HttpOnly; SameSite=Lax",
            cognitoEnabled: "Path=/; Secure; SameSite=Lax",
        };
    }
    throw new Error(`Cannot determine default cookiesettings for ${props.mode} with compatibility ${props.compatibility}`);
}
function isCompleteConfig(config) {
    return config["userPoolArn"] !== undefined;
}
var LogLevel;
(function (LogLevel) {
    LogLevel[LogLevel["none"] = 0] = "none";
    LogLevel[LogLevel["error"] = 10] = "error";
    LogLevel[LogLevel["warn"] = 20] = "warn";
    LogLevel[LogLevel["info"] = 30] = "info";
    LogLevel[LogLevel["debug"] = 40] = "debug";
})(LogLevel || (LogLevel = {}));
class Logger {
    constructor(logLevel) {
        this.logLevel = logLevel;
    }
    jsonify(args) {
        return args.map((arg) => {
            if (typeof arg === "object") {
                try {
                    return JSON.stringify(arg);
                }
                catch {
                    return arg;
                }
            }
            return arg;
        });
    }
    info(...args) {
        if (this.logLevel >= LogLevel.info) {
            console.log(...this.jsonify(args));
        }
    }
    warn(...args) {
        if (this.logLevel >= LogLevel.warn) {
            console.warn(...this.jsonify(args));
        }
    }
    error(...args) {
        if (this.logLevel >= LogLevel.error) {
            console.error(...this.jsonify(args));
        }
    }
    debug(...args) {
        if (this.logLevel >= LogLevel.debug) {
            console.trace(...this.jsonify(args));
        }
    }
}
function getConfig() {
    const config = JSON.parse(fs_1.readFileSync(`${__dirname}/configuration.json`).toString("utf8"));
    return {
        cloudFrontHeaders: asCloudFrontHeaders(config.httpHeaders),
        logger: new Logger(LogLevel[config.logLevel]),
        ...config,
    };
}
exports.getConfig = getConfig;
function getCompleteConfig() {
    const config = getConfig();
    if (!isCompleteConfig(config)) {
        throw new Error("Incomplete config in configuration.json");
    }
    // Derive the issuer and JWKS uri all JWT's will be signed with from the User Pool's ID and region:
    const userPoolId = config.userPoolArn.split("/")[1];
    const userPoolRegion = userPoolId.match(/^(\S+?)_\S+$/)[1];
    const tokenIssuer = `https://cognito-idp.${userPoolRegion}.amazonaws.com/${userPoolId}`;
    const tokenJwksUri = `${tokenIssuer}/.well-known/jwks.json`;
    // Derive cookie settings by merging the defaults with the explicitly provided values
    const defaultCookieSettings = getDefaultCookieSettings({
        compatibility: config.cookieCompatibility,
        mode: config.mode,
    });
    const cookieSettings = config.cookieSettings
        ? Object.fromEntries(Object.entries({
            ...defaultCookieSettings,
            ...config.cookieSettings,
        }).map(([k, v]) => [
            k,
            v || defaultCookieSettings[k],
        ]))
        : defaultCookieSettings;
    // Defaults for nonce and PKCE
    const defaults = {
        secretAllowedCharacters: "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~",
        pkceLength: 43,
        nonceLength: 16,
        nonceMaxAge: ((cookieSettings === null || cookieSettings === void 0 ? void 0 : cookieSettings.nonce) &&
            parseInt(cookie_1.parse(cookieSettings.nonce.toLowerCase())["max-age"])) ||
            60 * 60 * 24,
    };
    return {
        ...defaults,
        ...config,
        cookieSettings,
        tokenIssuer,
        tokenJwksUri,
    };
}
exports.getCompleteConfig = getCompleteConfig;
function extractCookiesFromHeaders(headers) {
    // Cookies are present in the HTTP header "Cookie" that may be present multiple times.
    // This utility function parses occurrences  of that header and splits out all the cookies and their values
    // A simple object is returned that allows easy access by cookie name: e.g. cookies["nonce"]
    if (!headers["cookie"]) {
        return {};
    }
    const cookies = headers["cookie"].reduce((reduced, header) => Object.assign(reduced, cookie_1.parse(header.value)), {});
    return cookies;
}
function withCookieDomain(distributionDomainName, cookieSettings) {
    // Add the domain to the cookiesetting
    if (cookieSettings.toLowerCase().indexOf("domain") === -1) {
        // Add leading dot for compatibility with Amplify (or js-cookie really)
        return `${cookieSettings}; Domain=.${distributionDomainName}`;
    }
    return cookieSettings;
}
function asCloudFrontHeaders(headers) {
    // Turn a regular key-value object into the explicit format expected by CloudFront
    return Object.entries(headers).reduce((reduced, [key, value]) => Object.assign(reduced, {
        [key.toLowerCase()]: [
            {
                key,
                value,
            },
        ],
    }), {});
}
exports.asCloudFrontHeaders = asCloudFrontHeaders;
function getAmplifyCookieNames(clientId, cookiesOrUserName) {
    const keyPrefix = `CognitoIdentityServiceProvider.${clientId}`;
    const lastUserKey = `${keyPrefix}.LastAuthUser`;
    let tokenUserName;
    if (typeof cookiesOrUserName === "string") {
        tokenUserName = cookiesOrUserName;
    }
    else {
        tokenUserName = cookiesOrUserName[lastUserKey];
    }
    return {
        lastUserKey,
        userDataKey: `${keyPrefix}.${tokenUserName}.userData`,
        scopeKey: `${keyPrefix}.${tokenUserName}.tokenScopesString`,
        idTokenKey: `${keyPrefix}.${tokenUserName}.idToken`,
        accessTokenKey: `${keyPrefix}.${tokenUserName}.accessToken`,
        refreshTokenKey: `${keyPrefix}.${tokenUserName}.refreshToken`,
    };
}
exports.getAmplifyCookieNames = getAmplifyCookieNames;
function getElasticsearchCookieNames() {
    return {
        idTokenKey: "ID-TOKEN",
        accessTokenKey: "ACCESS-TOKEN",
        refreshTokenKey: "REFRESH-TOKEN",
        cognitoEnabledKey: "COGNITO-ENABLED",
    };
}
exports.getElasticsearchCookieNames = getElasticsearchCookieNames;
function extractAndParseCookies(headers, clientId, cookieCompatibility) {
    const cookies = extractCookiesFromHeaders(headers);
    if (!cookies) {
        return {};
    }
    let cookieNames;
    if (cookieCompatibility === "amplify") {
        cookieNames = getAmplifyCookieNames(clientId, cookies);
    }
    else {
        cookieNames = getElasticsearchCookieNames();
    }
    return {
        tokenUserName: cookies[cookieNames.lastUserKey],
        idToken: cookies[cookieNames.idTokenKey],
        accessToken: cookies[cookieNames.accessTokenKey],
        refreshToken: cookies[cookieNames.refreshTokenKey],
        scopes: cookies[cookieNames.scopeKey],
        nonce: cookies["spa-auth-edge-nonce"],
        nonceHmac: cookies["spa-auth-edge-nonce-hmac"],
        pkce: cookies["spa-auth-edge-pkce"],
    };
}
exports.extractAndParseCookies = extractAndParseCookies;
exports.generateCookieHeaders = {
    newTokens: (param) => _generateCookieHeaders({ ...param, event: "newTokens" }),
    signOut: (param) => _generateCookieHeaders({ ...param, event: "signOut" }),
    refreshFailed: (param) => _generateCookieHeaders({ ...param, event: "refreshFailed" }),
};
function _generateCookieHeaders(param) {
    /*
      Generate cookie headers for the following scenario's:
        - new tokens: called from Parse Auth and Refresh Auth lambda, when receiving fresh JWT's from Cognito
        - sign out: called from Sign Out Lambda, when the user visits the sign out URL
        - refresh failed: called from Refresh Auth lambda when the refresh failed (e.g. because the refresh token has expired)
  
      Note that there are other places besides this helper function where cookies can be set (search codebase for "set-cookie")
      */
    const decodedIdToken = decodeToken(param.tokens.id_token);
    const tokenUserName = decodedIdToken["cognito:username"];
    let cookies;
    let cookieNames;
    if (param.cookieCompatibility === "amplify") {
        cookieNames = getAmplifyCookieNames(param.clientId, tokenUserName);
        const userData = JSON.stringify({
            UserAttributes: [
                {
                    Name: "sub",
                    Value: decodedIdToken["sub"],
                },
                {
                    Name: "email",
                    Value: decodedIdToken["email"],
                },
            ],
            Username: tokenUserName,
        });
        // Construct object with the cookies
        cookies = {
            [cookieNames.lastUserKey]: `${tokenUserName}; ${withCookieDomain(param.domainName, param.cookieSettings.idToken)}`,
            [cookieNames.scopeKey]: `${param.oauthScopes.join(" ")}; ${withCookieDomain(param.domainName, param.cookieSettings.accessToken)}`,
            [cookieNames.userDataKey]: `${encodeURIComponent(userData)}; ${withCookieDomain(param.domainName, param.cookieSettings.idToken)}`,
            "amplify-signin-with-hostedUI": `true; ${withCookieDomain(param.domainName, param.cookieSettings.accessToken)}`,
        };
    }
    else {
        cookieNames = getElasticsearchCookieNames();
        cookies = {
            [cookieNames.cognitoEnabledKey]: `True; ${withCookieDomain(param.domainName, param.cookieSettings.cognitoEnabled)}`,
        };
    }
    Object.assign(cookies, {
        [cookieNames.idTokenKey]: `${param.tokens.id_token}; ${withCookieDomain(param.domainName, param.cookieSettings.idToken)}`,
        [cookieNames.accessTokenKey]: `${param.tokens.access_token}; ${withCookieDomain(param.domainName, param.cookieSettings.accessToken)}`,
        [cookieNames.refreshTokenKey]: `${param.tokens.refresh_token}; ${withCookieDomain(param.domainName, param.cookieSettings.refreshToken)}`,
    });
    if (param.event === "signOut") {
        // Expire all cookies
        Object.keys(cookies).forEach((key) => (cookies[key] = expireCookie(cookies[key])));
    }
    else if (param.event === "refreshFailed") {
        // Expire refresh token (so the browser will not send it in vain again)
        cookies[cookieNames.refreshTokenKey] = expireCookie(cookies[cookieNames.refreshTokenKey]);
    }
    // Always expire nonce, nonceHmac and pkce - this is valid in all scenario's:
    // * event === 'newTokens' --> you just signed in and used your nonce and pkce successfully, don't need them no more
    // * event === 'refreshFailed' --> you are signed in already, why do you still have a nonce?
    // * event === 'signOut' --> clear ALL cookies anyway
    [
        "spa-auth-edge-nonce",
        "spa-auth-edge-nonce-hmac",
        "spa-auth-edge-pkce",
    ].forEach((key) => {
        cookies[key] = expireCookie();
    });
    // Return cookie object in format of CloudFront headers
    return Object.entries({
        ...param.additionalCookies,
        ...cookies,
    }).map(([k, v]) => ({ key: "set-cookie", value: `${k}=${v}` }));
}
function expireCookie(cookie = "") {
    const cookieParts = cookie
        .split(";")
        .map((part) => part.trim())
        .filter((part) => !part.toLowerCase().startsWith("max-age"))
        .filter((part) => !part.toLowerCase().startsWith("expires"));
    const expires = `Expires=${new Date(0).toUTCString()}`;
    const [, ...settings] = cookieParts; // first part is the cookie value, which we'll clear
    return ["", ...settings, expires].join("; ");
}
const AXIOS_INSTANCE = axios_1.default.create({
    httpsAgent: new https_1.Agent({ keepAlive: true }),
});
function decodeToken(jwt) {
    const tokenBody = jwt.split(".")[1];
    const decodableTokenBody = tokenBody.replace(/-/g, "+").replace(/_/g, "/");
    return JSON.parse(Buffer.from(decodableTokenBody, "base64").toString());
}
exports.decodeToken = decodeToken;
async function httpPostWithRetry(url, data, config, logger) {
    let attempts = 0;
    while (true) {
        ++attempts;
        try {
            return await AXIOS_INSTANCE.post(url, data, config);
        }
        catch (err) {
            logger.debug(`HTTP POST to ${url} failed (attempt ${attempts}):`);
            logger.debug((err.response && err.response.data) || err);
            if (attempts >= 5) {
                // Try 5 times at most
                logger.error(`No success after ${attempts} attempts, seizing further attempts`);
                throw err;
            }
            if (attempts >= 2) {
                // After attempting twice immediately, do some exponential backoff with jitter
                logger.debug("Doing exponential backoff with jitter, before attempting HTTP POST again ...");
                await new Promise((resolve) => setTimeout(resolve, 25 * (Math.pow(2, attempts) + Math.random() * attempts)));
                logger.debug("Done waiting, will try HTTP POST again now");
            }
        }
    }
}
exports.httpPostWithRetry = httpPostWithRetry;
function createErrorHtml(props) {
    const params = { ...props, region: process.env.AWS_REGION };
    return template_html_1.default.replace(/\${([^}]*)}/g, (_, v) => params[v] || "");
}
exports.createErrorHtml = createErrorHtml;
exports.urlSafe = {
    /*
          Functions to translate base64-encoded strings, so they can be used:
          - in URL's without needing additional encoding
          - in OAuth2 PKCE verifier
          - in cookies (to be on the safe side, as = + / are in fact valid characters in cookies)
  
          stringify:
              use this on a base64-encoded string to translate = + / into replacement characters
  
          parse:
              use this on a string that was previously urlSafe.stringify'ed to return it to
              its prior pure-base64 form. Note that trailing = are not added, but NodeJS does not care
      */
    stringify: (b64encodedString) => b64encodedString.replace(/=/g, "").replace(/\+/g, "-").replace(/\//g, "_"),
    parse: (b64encodedString) => b64encodedString.replace(/-/g, "+").replace(/_/g, "/"),
};
function sign(stringToSign, secret, signatureLength) {
    const digest = crypto_1.createHmac("sha256", secret)
        .update(stringToSign)
        .digest("base64")
        .slice(0, signatureLength);
    const signature = exports.urlSafe.stringify(digest);
    return signature;
}
exports.sign = sign;
function timestampInSeconds() {
    return (Date.now() / 1000) | 0;
}
exports.timestampInSeconds = timestampInSeconds;
async function validateAndCheckIdToken(idToken, config) {
    config.logger.info("Validating JWT ...");
    let idTokenPayload = await validate_jwt_1.validate(idToken, config.tokenJwksUri, config.tokenIssuer, config.clientId);
    config.logger.info("JWT is valid");
    // Check that the ID token has the required group.
    if (config.requiredGroup) {
        let cognitoGroups = idTokenPayload["cognito:groups"];
        if (!cognitoGroups) {
            throw new MissingRequiredGroupError("Token does not have any groups");
        }
        if (!cognitoGroups.includes(config.requiredGroup)) {
            throw new MissingRequiredGroupError("Token does not have required group");
        }
        config.logger.info("JWT has requiredGroup");
    }
}
exports.validateAndCheckIdToken = validateAndCheckIdToken;
class MissingRequiredGroupError extends Error {
}
exports.MissingRequiredGroupError = MissingRequiredGroupError;
