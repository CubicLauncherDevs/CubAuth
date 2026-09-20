import { base64, bytes, compactUuid, signProperty } from './crypto';
import type { Env, Profile, Session } from './types';

export const briefProfile = (p: Profile) => ({ id: compactUuid(p.id), name: p.name });

export function sessionResponse(session: Session, accessToken: string, requestUser: boolean, authenticate = false) {
  return {
    accessToken,
    clientToken: session.client_token,
    ...(authenticate ? { availableProfiles: [briefProfile(session.profile)] } : {}),
    selectedProfile: briefProfile(session.profile),
    ...(requestUser ? { user: { id: compactUuid(session.user_id), properties: [] } } : {}),
  };
}

export async function fullProfile(profile: Profile, env: Env, signed: boolean) {
  const textures = profile.skin_hash ? {
    SKIN: {
      url: `${env.SUPABASE_URL.replace(/\/$/, '')}/storage/v1/object/public/skins/${profile.skin_hash}`,
      ...(profile.skin_model === 'slim' ? { metadata: { model: 'slim' } } : {}),
    },
  } : {};
  const value = base64(bytes(JSON.stringify({
    timestamp: Date.now(), profileId: compactUuid(profile.id), profileName: profile.name,
    ...(signed ? { signatureRequired: true } : {}), textures,
  })));
  const properties: { name: string; value: string; signature?: string }[] = [
    { name: 'textures', value }, { name: 'uploadableTextures', value: 'skin' },
  ];
  if (signed) {
    for (const property of properties) property.signature = await signProperty(property.value, env);
  }
  return { ...briefProfile(profile), properties };
}
