// Outbound email (invitations now; the §5 notifier later). The message carries secrets (invite links),
// so it is never logged: failures are reported by code only.
import { createTransport } from "nodemailer";

export interface MailMessage {
  to: string;
  subject: string;
  text: string;
}

export interface Mailer {
  send(m: MailMessage): Promise<void>;
}

/** SMTP via nodemailer; `url` like smtp://user:pass@host:587 (Mailpit locally: smtp://127.0.0.1:1025). */
export function smtpMailer(url: string, from: string): Mailer {
  const t = createTransport(url);
  return {
    async send(m) {
      await t.sendMail({ from, ...m });
    },
  };
}
