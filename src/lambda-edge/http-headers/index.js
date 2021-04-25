"use strict";
// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0
Object.defineProperty(exports, "__esModule", { value: true });
exports.handler = void 0;
const shared_1 = require("../shared/shared");
let CONFIG;
exports.handler = async (event) => {
    if (!CONFIG) {
        CONFIG = shared_1.getConfig();
        CONFIG.logger.debug("Configuration loaded:", CONFIG);
    }
    CONFIG.logger.debug("Event:", event);
    const response = event.Records[0].cf.response;
    Object.assign(response.headers, CONFIG.cloudFrontHeaders);
    CONFIG.logger.debug("Returning response:\n", response);
    return response;
};
