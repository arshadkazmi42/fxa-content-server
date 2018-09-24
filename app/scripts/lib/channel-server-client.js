/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

import a256gcm from './crypto/a256gcm';
import { pick } from 'underscore';
import base64 from './base64';
import { DEVICE_PAIRING_CHANNEL_KEY_BYTES } from './constants';
import { Model } from 'backbone';
import hkdf from './crypto/hkdf';

const CHANNEL_KEY_INFO_BUFFER = Buffer.from('identity.mozilla.com/picl/v1/pair/encryption-key', 'utf8');
const CONFIRMATION_CODE_INFO_BUFFER = Buffer.from('identity.mozilla.com/picl/v1/pair/confirmation-code', 'utf8');

const CONFIRMATION_CODE_LENGTH = 4;

export default class ChannelServerClient extends Model {
  constructor (attrs = {}, options = {}) {
    super(attrs, options);

    this._channelServerUrl = options.channelServerUrl;
    this._notifier = options.notifier;
  }

  attachToExisting (channelId = this.get('channelId')) {
    const firstMessageHandler = (event) => {
      // the first event is always the channel identifier, we already have that
      // so can drop the message on the ground.
      this.socket.removeEventListener('message', firstMessageHandler);
      this.socket.addEventListener('message', (event) => this.encryptedMessageHandler(event));

      this.trigger('connected');
    };

    const existingChannelUrl = `${this._channelServerUrl}${channelId}`;
    this.openSocket(existingChannelUrl, firstMessageHandler);
  }

  openSocket (url, firstMessageHandler) {
    this.socket = new WebSocket(url);
    this.socket.addEventListener('open', () => {
      this.trigger('open');
    });
    this.socket.addEventListener('close', () => {
      this.trigger('close');
    });
    this.socket.addEventListener('error', (event) => {
      this.trigger('error', event);
    });
    this.socket.addEventListener('message', firstMessageHandler);
  }

  encryptedMessageHandler (event) {
    const { message: ciphertext, sender } = JSON.parse(event.data);
    this._decrypt(ciphertext).then(decrypted => {
      const { data, message } = decrypted;

      data.channelServerClient = this;
      data.remoteMetaData = pick(sender, 'city', 'country', 'region', 'ua');

      this.trigger(message, data);
      this._notifier.trigger(message, data);
    });
  }

  send (message, data = {}) {
    const envelope = {
      data,
      message,
    };

    return this._encrypt(envelope)
      .then(bundle => this.socket.send(bundle));
  }

  _decrypt (ciphertext) {
    return this._getChannelJwk()
      .then(keysJwk => a256gcm.decrypt(ciphertext, keysJwk))
      .then(result => JSON.parse(result));
  }

  _encrypt (envelope) {
    return this._getChannelJwk()
      .then(keysJwk => a256gcm.encrypt(JSON.stringify(envelope), keysJwk));
  }

  _getChannelJwk () {
    const { channelId, channelJWK, channelKey } = this.toJSON();
    if (channelJWK) {
      return Promise.resolve(channelJWK);
    }

    const channelKeyBuffer = Buffer.from(base64.base64UrlToBase64(channelKey), 'base64');
    const channelIdBuffer = Buffer.from(channelId, 'utf8');

    return Promise.all([
      this._deriveChannelJwk(channelKeyBuffer, channelIdBuffer),
      this._deriveConfirmationCode(channelKeyBuffer, channelIdBuffer),
    ]).then(() => this.get('channelJWK'));
  }

  _deriveChannelJwk(channelKeyBuffer, channelIdBuffer) {
    return hkdf(channelKeyBuffer, channelIdBuffer, CHANNEL_KEY_INFO_BUFFER, DEVICE_PAIRING_CHANNEL_KEY_BYTES)
      .then(keyBuffer => a256gcm.createJwkFromKey(keyBuffer))
      .then(channelJWK => this.set({ channelJWK }));
  }

  _deriveConfirmationCode(channelKeyBuffer, channelIdBuffer) {
    return hkdf(channelKeyBuffer, channelIdBuffer, CONFIRMATION_CODE_INFO_BUFFER, CONFIRMATION_CODE_LENGTH)
      .then(confirmationCodeBuffer => confirmationCodeBuffer.toString('hex'))
      .then(confirmationCode => this.set({ confirmationCode }));
  }

  close () {

  }
}
