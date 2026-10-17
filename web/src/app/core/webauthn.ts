// WebAuthn options travel as JSON with binary fields base64url-encoded.
// Browsers that implement the JSON helpers of WebAuthn Level 3 convert
// them natively; the fallbacks cover the rest.

type Json = Record<string, unknown>;

export function supported(): boolean {
  return typeof window !== 'undefined' && 'PublicKeyCredential' in window;
}

function fromBase64url(s: string): ArrayBuffer {
  const b64 = s
    .replace(/-/g, '+')
    .replace(/_/g, '/')
    .padEnd(Math.ceil(s.length / 4) * 4, '=');
  const bin = atob(b64);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) {
    bytes[i] = bin.charCodeAt(i);
  }
  return bytes.buffer;
}

function toBase64url(buf: ArrayBuffer): string {
  let bin = '';
  for (const b of new Uint8Array(buf)) {
    bin += String.fromCharCode(b);
  }
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function decodeDescriptors(list: unknown): PublicKeyCredentialDescriptor[] | undefined {
  if (!Array.isArray(list)) {
    return undefined;
  }
  return list.map(
    (d: Json) => ({ ...d, id: fromBase64url(d['id'] as string) }) as PublicKeyCredentialDescriptor,
  );
}

type PKC = typeof PublicKeyCredential & {
  parseCreationOptionsFromJSON?: (o: Json) => PublicKeyCredentialCreationOptions;
  parseRequestOptionsFromJSON?: (o: Json) => PublicKeyCredentialRequestOptions;
};

export function creationOptions(json: Json): PublicKeyCredentialCreationOptions {
  const pkc = PublicKeyCredential as PKC;
  if (pkc.parseCreationOptionsFromJSON) {
    return pkc.parseCreationOptionsFromJSON(json);
  }

  const user = json['user'] as Json;
  return {
    ...json,
    challenge: fromBase64url(json['challenge'] as string),
    user: { ...user, id: fromBase64url(user['id'] as string) },
    excludeCredentials: decodeDescriptors(json['excludeCredentials']),
  } as unknown as PublicKeyCredentialCreationOptions;
}

export function requestOptions(json: Json): PublicKeyCredentialRequestOptions {
  const pkc = PublicKeyCredential as PKC;
  if (pkc.parseRequestOptionsFromJSON) {
    return pkc.parseRequestOptionsFromJSON(json);
  }

  return {
    ...json,
    challenge: fromBase64url(json['challenge'] as string),
    allowCredentials: decodeDescriptors(json['allowCredentials']),
  } as unknown as PublicKeyCredentialRequestOptions;
}

// Serializes a credential the way the service's WebAuthn parser expects.
export function toJSON(cred: PublicKeyCredential): object {
  if ('toJSON' in cred && typeof cred.toJSON === 'function') {
    return cred.toJSON();
  }

  const r = cred.response;
  const response: Json = { clientDataJSON: toBase64url(r.clientDataJSON) };

  if (r instanceof AuthenticatorAttestationResponse) {
    response['attestationObject'] = toBase64url(r.attestationObject);
    response['transports'] = r.getTransports?.() ?? [];
  } else if (r instanceof AuthenticatorAssertionResponse) {
    response['authenticatorData'] = toBase64url(r.authenticatorData);
    response['signature'] = toBase64url(r.signature);
    if (r.userHandle) {
      response['userHandle'] = toBase64url(r.userHandle);
    }
  }

  return {
    id: cred.id,
    rawId: toBase64url(cred.rawId),
    type: cred.type,
    response,
    authenticatorAttachment: cred.authenticatorAttachment ?? undefined,
    clientExtensionResults: cred.getClientExtensionResults(),
  };
}

export const forTesting = { fromBase64url, toBase64url };
