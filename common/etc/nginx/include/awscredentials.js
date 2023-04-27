/*
 *  Copyright 2023 F5, Inc.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

import utils from "./utils.js";

const fs = require('fs');

/**
 * Get the current session token from either the instance profile credential 
 * cache or environment variables.
 *
 * @param r {Request} HTTP request object (not used, but required for NGINX configuration)
 * @returns {string} current session token or empty string
 */
function sessionToken(r) {
    const credentials = readCredentials(r);
    if (credentials.sessionToken) {
        return credentials.sessionToken;
    }
    return '';
}

/**
 * Get the instance profile credentials needed to authenticated against S3 from
 * a backend cache. If the credentials cannot be found, then return undefined.
 * @param r {Request} HTTP request object (not used, but required for NGINX configuration)
 * @returns {undefined|{accessKeyId: (string), secretAccessKey: (string), sessionToken: (string|null), expiration: (string|null)}} AWS instance profile credentials or undefined
 */
function readCredentials(r) {
    // TODO: Change the generic constants naming for multiple AWS services.
    if ('S3_ACCESS_KEY_ID' in process.env && 'S3_SECRET_KEY' in process.env) {
        const sessionToken = 'S3_SESSION_TOKEN' in process.env ?
            process.env['S3_SESSION_TOKEN'] : null;
        var keyObj = getAccessKeyByBucketName(r);
        utils.debug_log(r, "Use " + keyObj.s3_access_key_id + "/" + keyObj.s3_secret_key + " for " + decodeURIComponent(r.variables.uri_path));
        if (keyObj) {
            return {
                accessKeyId: keyObj.s3_access_key_id,
                secretAccessKey: keyObj.s3_secret_key,
                sessionToken: sessionToken,
                expiration: null
            };
        }
        return {
            accessKeyId: process.env['S3_ACCESS_KEY_ID'],
            secretAccessKey: process.env['S3_SECRET_KEY'],
            sessionToken: sessionToken,
            expiration: null
        };
    }

    if ("variables" in r && r.variables.cache_instance_credentials_enabled == 1) {
        return _readCredentialsFromKeyValStore(r);
    } else {
        return _readCredentialsFromFile();
    }
}

/**
 * get access keys by bucket name in url
*/
function getAccessKeyByBucketName(r) {
    var bjson = getBucketMapFromFile(r);
    const uriPath = decodeURIComponent(r.variables.uri_path);
    const reqBucketName = uriPath.split('/')[1];
    return bjson[reqBucketName];
}

/**
 * Read bucket map from file and convert to json
*/
function getBucketMapFromFile(r) {
    const bucketMap = fs.readFileSync(process.env['BUCKET_MAP_FILE']);
    var bucketJson = JSON.parse(bucketMap);
    for (const bucketName in bucketJson) {
        let logstr = "";
        logstr += "BUCKET_NAME=" + bucketName;
        logstr += ", " + "S3_ACCESS_KEY_ID=" + bucketJson[bucketName].s3_access_key_id;
        logstr += ", " + "S3_SECRET_KEY=" + bucketJson[bucketName].s3_secret_key;
        utils.debug_log(r, logstr);
    }
    return bucketJson;
}

/**
 * Read credentials from the NGINX Keyval store. If it is not found, then
 * return undefined.
 *
 * @param r {Request} HTTP request object (not used, but required for NGINX configuration)
 * @returns {undefined|{accessKeyId: (string), secretAccessKey: (string), sessionToken: (string), expiration: (string)}} AWS instance profile credentials or undefined
 * @private
 */
function _readCredentialsFromKeyValStore(r) {
    const cached = r.variables.instance_credential_json;

    if (!cached) {
        return undefined;
    }

    try {
        return JSON.parse(cached);
    } catch (e) {
        utils.debug_log(r, `Error parsing JSON value from r.variables.instance_credential_json: ${e}`);
        return undefined;
    }
}

/**
 * Read the contents of the credentials file into memory. If it is not
 * found, then return undefined.
 *
 * @returns {undefined|{accessKeyId: (string), secretAccessKey: (string), sessionToken: (string), expiration: (string)}} AWS instance profile credentials or undefined
 * @private
 */
function _readCredentialsFromFile() {
    const credsFilePath = _credentialsTempFile();

    try {
        const creds = fs.readFileSync(credsFilePath);
        return JSON.parse(creds);
    } catch (e) {
        /* Do not throw an exception in the case of when the
           credentials file path is invalid in order to signal to
           the caller that such a file has not been created yet. */
        if (e.code === 'ENOENT') {
            return undefined;
        }
        throw e;
    }
}

/**
 * Returns the path to the credentials temporary cache file.
 *
 * @returns {string} path on the file system to credentials cache file
 * @private
 */
function _credentialsTempFile() {
    if (process.env['S3_CREDENTIALS_TEMP_FILE']) {
        return process.env['S3_CREDENTIALS_TEMP_FILE'];
    }
    if (process.env['TMPDIR']) {
        return `${process.env['TMPDIR']}/credentials.json`
    }

    return '/tmp/credentials.json';
}

/**
 * Write the instance profile credentials to a caching backend.
 *
 * @param r {Request} HTTP request object (not used, but required for NGINX configuration)
 * @param credentials {{accessKeyId: (string), secretAccessKey: (string), sessionToken: (string), expiration: (string)}} AWS instance profile credentials
 */
function writeCredentials(r, credentials) {
    /* Do not bother writing credentials if we are running in a mode where we
       do not need instance credentials. */
    if (process.env['S3_ACCESS_KEY_ID'] && process.env['S3_SECRET_KEY']) {
        return;
    }

    if (!credentials) {
        throw `Cannot write invalid credentials: ${JSON.stringify(credentials)}`;
    }

    if ("variables" in r && r.variables.cache_instance_credentials_enabled == 1) {
        _writeCredentialsToKeyValStore(r, credentials);
    } else {
        _writeCredentialsToFile(credentials);
    }
}

/**
 * Write the instance profile credentials to the NGINX Keyval store.
 *
 * @param r {Request} HTTP request object (not used, but required for NGINX configuration)
 * @param credentials {{accessKeyId: (string), secretAccessKey: (string), sessionToken: (string), expiration: (string)}} AWS instance profile credentials
 * @private
 */
function _writeCredentialsToKeyValStore(r, credentials) {
    r.variables.instance_credential_json = JSON.stringify(credentials);
}

/**
 * Write the instance profile credentials to a file on the file system. This
 * file will be quite small and should end up in the file cache relatively
 * quickly if it is repeatedly read.
 *
 * @param r {Request} HTTP request object (not used, but required for NGINX configuration)
 * @param credentials {{accessKeyId: (string), secretAccessKey: (string), sessionToken: (string), expiration: (string)}} AWS instance profile credentials
 * @private
 */
function _writeCredentialsToFile(credentials) {
    fs.writeFileSync(_credentialsTempFile(), JSON.stringify(credentials));
}

export default {
    readCredentials,
    sessionToken,
    writeCredentials
}
