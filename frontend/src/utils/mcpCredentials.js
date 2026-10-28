export function isCompleteMcpKey(value) {
  return typeof value === 'string' && /^arl_mcp_[A-Za-z0-9_-]{32,}$/.test(value.trim());
}

export function resolveMcpCredential(selectedKeyId, sessionToken, keySecrets) {
  if (selectedKeyId === 'current_session') return sessionToken || '';
  const value = keySecrets[selectedKeyId]?.trim() || '';
  return isCompleteMcpKey(value) ? value : '';
}
