-- TOTP replay protection.
--
-- totp_last_step is the highest 30-second counter a code was accepted for.
-- Without it, a code observed once stays valid for the whole ±1 step skew
-- window, so an attacker who captures it can authenticate again.
ALTER TABLE users
    ADD COLUMN IF NOT EXISTS totp_last_step BIGINT NOT NULL DEFAULT 0;
