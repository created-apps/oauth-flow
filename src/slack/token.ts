import { env } from '../config/env';

/**
 * Accessor for the static workspace Slack bot token (xoxb-...).
 * Used directly by server-side background tasks/automations (not OAuth).
 * Throws a clear error if SLACK_BOT_TOKEN is not set in environment.
 */
export function getSlackBotToken(): string {
  if (!env.SLACK_BOT_TOKEN || env.SLACK_BOT_TOKEN.trim().length === 0) {
    throw new Error('SLACK_BOT_TOKEN is not configured');
  }
  return env.SLACK_BOT_TOKEN.trim();
}
