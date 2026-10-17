// Shapes of the identity API (see transport/http in the Go service).

export type Provider = 'google' | 'line' | 'passkeys';

export type Status = 'pending' | 'registered' | 'activated' | 'locked' | 'revoked';

export interface SocialAccount {
  social_id: string;
  social_provider: Provider;
  created_at: string;
}

export interface User {
  id: string;
  username: string;
  name: string;
  email: string;
  status: Status;
  accounts: SocialAccount[];
  avatar: string;
  created_at: string;
}

export interface Token {
  token: string;
  expired_at: string;
}

export interface SignInResponse {
  user: User;
  token: Token;
}

export interface FrontendConfig {
  google_client_id?: string;
  line: boolean;
  passkeys: boolean;
}

export interface ErrorResponse {
  error: string;
  message: string;
}

export const API = '/identity/v1';
