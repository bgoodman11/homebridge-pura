// src/puraCognitoClient.ts

import {
  CognitoIdentityProviderClient,
  InitiateAuthCommand,
  RespondToAuthChallengeCommand,
  AuthFlowType,
} from '@aws-sdk/client-cognito-identity-provider';
import { Logging } from 'homebridge';

export interface PuraTokens {
  accessToken: string;
  idToken: string;
  refreshToken: string;
}

export class PuraCognitoClient {
  private readonly client: CognitoIdentityProviderClient;
  private readonly clientId: string;
  private readonly log: Logging;

  constructor(opts: { region: string; clientId: string; log: Logging }) {
    this.clientId = opts.clientId;
    this.log = opts.log;

    this.client = new CognitoIdentityProviderClient({
      region: opts.region,
    });
  }

  /**
   * Login with username + password.
   *
   * NOTE: This implementation uses USER_PASSWORD_AUTH for simplicity.
   * If Pura's app client only allows USER_SRP_AUTH, this will fail with
   * NotAuthorizedException / InvalidParameter / similar, and we'll need
   * to switch to an SRP-based flow here.
   */
  async login(username: string, password: string): Promise<PuraTokens> {
    this.log.debug('[PuraCognitoClient] Initiating login for', username);

    const cmd = new InitiateAuthCommand({
      AuthFlow: AuthFlowType.USER_PASSWORD_AUTH,
      ClientId: this.clientId,
      AuthParameters: {
        USERNAME: username,
        PASSWORD: password,
      },
    });

    const resp = await this.client.send(cmd);

    if (!resp.AuthenticationResult) {
      // If there is a challenge (MFA, NEW_PASSWORD_REQUIRED, etc.), we’d handle
      // it here via RespondToAuthChallengeCommand. For now, assume no challenge.
      const challenge = resp.ChallengeName ?? 'Unknown';
      this.log.error(
        `[PuraCognitoClient] Unexpected challenge or missing tokens. Challenge: ${challenge}`,
      );
      throw new Error(
        `Pura authentication failed: unexpected challenge (${challenge})`,
      );
    }

    const {
      AccessToken,
      IdToken,
      RefreshToken,
    } = resp.AuthenticationResult;

    if (!AccessToken || !IdToken || !RefreshToken) {
      this.log.error(
        '[PuraCognitoClient] Missing one or more tokens in AuthenticationResult',
      );
      throw new Error('Pura authentication failed: missing tokens');
    }

    this.log.debug('[PuraCognitoClient] Login successful');
    return {
      accessToken: AccessToken,
      idToken: IdToken,
      refreshToken: RefreshToken,
    };
  }

  /**
   * Refresh an existing session using a refresh token.
   */
  async refresh(refreshToken: string): Promise<PuraTokens> {
    this.log.debug('[PuraCognitoClient] Refreshing tokens');

    const cmd = new InitiateAuthCommand({
      AuthFlow: AuthFlowType.REFRESH_TOKEN_AUTH,
      ClientId: this.clientId,
      AuthParameters: {
        REFRESH_TOKEN: refreshToken,
      },
    });

    const resp = await this.client.send(cmd);

    if (!resp.AuthenticationResult) {
      this.log.error(
        '[PuraCognitoClient] Missing AuthenticationResult during refresh',
      );
      throw new Error('Pura token refresh failed: no AuthenticationResult');
    }

    const {
      AccessToken,
      IdToken,
      RefreshToken,
    } = resp.AuthenticationResult;

    // Some flows don’t return a new refresh token; keep the old one if so.
    const finalRefresh = RefreshToken ?? refreshToken;

    if (!AccessToken || !IdToken || !finalRefresh) {
      this.log.error(
        '[PuraCognitoClient] Missing one or more tokens in refresh result',
      );
      throw new Error('Pura token refresh failed: missing tokens');
    }

    this.log.debug('[PuraCognitoClient] Token refresh successful');
    return {
      accessToken: AccessToken,
      idToken: IdToken,
      refreshToken: finalRefresh,
    };
  }
}
