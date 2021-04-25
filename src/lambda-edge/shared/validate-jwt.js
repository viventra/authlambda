"use strict";
// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.validate = void 0;
const jsonwebtoken_1 = require("jsonwebtoken");
const jwks_rsa_1 = __importDefault(require("jwks-rsa"));
// jwks client is cached at this scope so it can be reused across Lambda invocations
let jwksRsa;
function isRsaSigningKey(key) {
    return !!key.rsaPublicKey;
}
async function getSigningKey(jwksUri, kid) {
    // Retrieves the public key that corresponds to the private key with which the token was signed
    if (!jwksRsa) {
        jwksRsa = jwks_rsa_1.default({ cache: true, rateLimit: true, jwksUri });
    }
    return new Promise((resolve, reject) => jwksRsa.getSigningKey(kid, (err, jwk) => err
        ? reject(err)
        : resolve(isRsaSigningKey(jwk) ? jwk.rsaPublicKey : jwk.publicKey)));
}
async function validate(jwtToken, jwksUri, issuer, audience) {
    const decodedToken = jsonwebtoken_1.decode(jwtToken, { complete: true });
    if (!decodedToken) {
        throw new Error("Cannot parse JWT token");
    }
    // The JWT contains a "kid" claim, key id, that tells which key was used to sign the token
    const kid = decodedToken["header"]["kid"];
    const jwk = await getSigningKey(jwksUri, kid);
    // Verify the JWT
    // This either rejects (JWT not valid), or resolves (JWT valid)
    const verificationOptions = {
        audience,
        issuer,
        ignoreExpiration: false,
    };
    // JWT's from Cognito are JSON objects
    return new Promise((resolve, reject) => jsonwebtoken_1.verify(jwtToken, jwk, verificationOptions, (err, decoded) => err ? reject(err) : resolve(decoded)));
}
exports.validate = validate;
