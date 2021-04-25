"use strict";
// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0
Object.defineProperty(exports, "__esModule", { value: true });
exports.handler = void 0;
const querystring_1 = require("querystring");
const shared_1 = require("../shared/shared");
let CONFIG;
exports.handler = async (event) => {
    if (!CONFIG) {
        CONFIG = shared_1.getCompleteConfig();
        CONFIG.logger.debug("Configuration loaded:", CONFIG);
    }
    CONFIG.logger.debug("Event:", event);
    const request = event.Records[0].cf.request;
    const domainName = request.headers["host"][0].value;
    let redirectedFromUri = `https://${domainName}`;
    try {
        const { requestedUri, nonce: currentNonce } = querystring_1.parse(request.querystring);
        redirectedFromUri += requestedUri || "";
        const { idToken, accessToken, refreshToken, nonce: originalNonce, } = shared_1.extractAndParseCookies(request.headers, CONFIG.clientId, CONFIG.cookieCompatibility);
        validateRefreshRequest(currentNonce, originalNonce, idToken, accessToken, refreshToken);
        let headers = {
            "Content-Type": "application/x-www-form-urlencoded",
        };
        if (CONFIG.clientSecret) {
            const encodedSecret = Buffer.from(`${CONFIG.clientId}:${CONFIG.clientSecret}`).toString("base64");
            headers["Authorization"] = `Basic ${encodedSecret}`;
        }
        let tokens = {
            id_token: idToken,
            access_token: accessToken,
            refresh_token: refreshToken,
        };
        let cookieHeadersEventType;
        try {
            const body = querystring_1.stringify({
                grant_type: "refresh_token",
                client_id: CONFIG.clientId,
                refresh_token: refreshToken,
            });
            const res = await shared_1.httpPostWithRetry(`https://${CONFIG.cognitoAuthDomain}/oauth2/token`, body, { headers }, CONFIG.logger).catch((err) => {
                throw new Error(`Failed to refresh tokens: ${err}`);
            });
            tokens.id_token = res.data.id_token;
            tokens.access_token = res.data.access_token;
            cookieHeadersEventType = "newTokens";
        }
        catch (err) {
            cookieHeadersEventType = "refreshFailed";
        }
        const response = {
            status: "307",
            statusDescription: "Temporary Redirect",
            headers: {
                location: [
                    {
                        key: "location",
                        value: redirectedFromUri,
                    },
                ],
                "set-cookie": shared_1.generateCookieHeaders[cookieHeadersEventType]({
                    tokens,
                    domainName,
                    ...CONFIG,
                }),
                ...CONFIG.cloudFrontHeaders,
            },
        };
        CONFIG.logger.debug("Returning response:\n", response);
        return response;
    }
    catch (err) {
        const response = {
            body: shared_1.createErrorHtml({
                title: "Refresh issue",
                message: "We can't refresh your sign-in because of a",
                expandText: "technical problem",
                details: err.toString(),
                linkUri: redirectedFromUri,
                linkText: "Try again",
            }),
            status: "200",
            headers: {
                ...CONFIG.cloudFrontHeaders,
                "content-type": [
                    {
                        key: "Content-Type",
                        value: "text/html; charset=UTF-8",
                    },
                ],
            },
        };
        CONFIG.logger.debug("Returning response:\n", response);
        return response;
    }
};
function validateRefreshRequest(currentNonce, originalNonce, idToken, accessToken, refreshToken) {
    if (!originalNonce) {
        throw new Error("Your browser didn't send the nonce cookie along, but it is required for security (prevent CSRF).");
    }
    else if (currentNonce !== originalNonce) {
        throw new Error("Nonce mismatch");
    }
    Object.entries({ idToken, accessToken, refreshToken }).forEach(([tokenType, token]) => {
        if (!token) {
            throw new Error(`Missing ${tokenType}`);
        }
    });
}
