/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

export default {
  /**
   * Convert a base64 string to a base64url string
   *
   * @param {String} base64Str
   * @returns {String}
   */
  base64ToBase64Url(base64Str) {
    return base64Str
      .replace(/\+/g, '-')
      .replace(/\//g, '_')
      .replace(/=/, '');
  },

  /**
   * Convert a base64url string to a base64 string
   *
   * @param {String} base64UrlStr
   * @returns {String}
   */
  base64UrlToBase64(base64UrlStr) {
    return base64UrlStr
      .replace(/-/g, '+')
      .replace(/_/g, '/');
  }
};
