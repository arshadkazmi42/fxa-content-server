/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

import AuthErrors from '../../lib/auth-errors';
import { CompleteState, State } from './state';
import PairingFlowStateMachine from './state-machine';

/* eslint-disable no-use-before-define */

class SupplicantState extends State {
  constructor (attributes, options = {}) {
    super(attributes, options);

    this.channelServerClient = options.channelServerClient;
    this.listenTo(this.channelServerClient, 'close', () => this.connectionClosed());
    this.listenTo(this.channelServerClient, 'error', () => this.connectionError());
  }

  connectionClosed () {
    this.navigate('pair/supp', {
      error: AuthErrors.toError('PAIRING_CHANNEL_CONNECTION_CLOSED')
    });
  }

  connectionError () {
    this.navigate('pair/supp', {
      error: AuthErrors.toError('PAIRING_CHANNEL_CONNECTION_ERROR')
    });
  }
}

class WaitForConnectionToChannelServer extends SupplicantState {
  name = 'WaitForConnectionToChannelServer';

  constructor (...args) {
    super(...args);

    this.listenTo(this.channelServerClient, 'connected', this.gotoSendOAuthRequestWaitForAccountMetadata);
  }

  connectionClosed () {
    // do nothing on connection closed
  }

  gotoSendOAuthRequestWaitForAccountMetadata () {
    this.gotoState(SendOAuthRequestWaitForAccountMetadata);
  }
}

class SendOAuthRequestWaitForAccountMetadata extends SupplicantState {
  name = 'WaitForAccountMetadata';

  constructor (...args) {
    super(...args);

    this.channelServerClient.send('pair:supp:request', this.relier.getPKCEParams());

    this.listenTo(this.notifier, 'pair:auth:metadata', this.gotoWaitForApprovals);
  }

  gotoWaitForApprovals (data) {
    this.broker.setRemoteMetaData(data.remoteMetaData);

    this.gotoState(WaitForApprovals, data);
  }
}


function onAuthAuthorize (NextState, result) {
  return Promise.resolve().then(() => {
    this.relier.validateApprovalData(result);

    const { code } = result;
    this.relier.set({ code });

    this.gotoState(NextState);
  }).catch(err => this.trigger('error', err));
}

class WaitForApprovals extends SupplicantState {
  name = 'WaitForApprovals';

  constructor (...args) {
    super(...args);

    this.navigate('pair/supp/allow', {
      deviceName: this.get('deviceName'),
      displayName: this.get('displayName'),
      email: this.get('email'),
      profileImageUrl: this.get('avatar'),
    });

    this.listenTo(this.notifier, 'pair:auth:authorize', this.onAuthorityAuthorize);
    this.listenTo(this.notifier, 'pair:supp:authorize', this.onSupplicantAuthorize);
  }

  onAuthorityAuthorize = onAuthAuthorize.bind(this, WaitForSupplicantAuthorize);

  onSupplicantAuthorize () {
    this.gotoState(WaitForAuthorityAuthorize);
  }
}

class WaitForSupplicantAuthorize extends SupplicantState {
  name = 'WaitForSupplicantAuthorize';

  constructor (...args) {
    super(...args);

    this.listenTo(this.notifier, 'pair:supp:authorize', this.onSuppAuthorize);
  }

  onSuppAuthorize () {
    this.gotoState(SendResultToRelier);
  }
}

class WaitForAuthorityAuthorize extends SupplicantState {
  name = 'WaitForAuthorityAuthorize';

  constructor (...args) {
    super(...args);
    this.navigate('/pair/supp/wait_for_auth');

    this.listenTo(this.notifier, 'pair:auth:authorize', this.onAuthorityAuthorize);
  }

  onAuthorityAuthorize = onAuthAuthorize.bind(this, SendResultToRelier);
}

class SendResultToRelier extends SupplicantState {
  name = 'SendResultToRelier';

  connectionClosed () {
    // do nothing, this is expected to happen
    // when pair:auth:authorize:ack is sent
    // to the remote end.
  }

  constructor (...args) {
    super(...args);

    // TODO - should the user be required to click a button
    // to go back to the relier?
    //this.navigate('/pair/supp/complete');

    // causes the channel to be closed by the remote end.
    // The connectionClosed handler of CompleteState will
    // do nothing.
    this.channelServerClient.send('pair:auth:authorize:ack');
    this.broker.sendCodeToRelier()
      .then(() => {
        this.gotoState(CompleteState);
      })
      .catch(err => this.trigger('error', err));
  }
}

class SupplicantStateMachine extends PairingFlowStateMachine {
  constructor(attrs, options = {}) {
    super(attrs, options);

    this.createState(WaitForConnectionToChannelServer);
  }
}

export default SupplicantStateMachine;

/* eslint-enable no-use-before-define */
