/* genkey.c - Generate a keypair
 * Copyright (C) 2002, 2003, 2004, 2007, 2010 Free Software Foundation, Inc.
 * Copyright (C) 2015 g10 Code GmbH.
 *
 * This file is part of GnuPG.
 *
 * GnuPG is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * GnuPG is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see <https://www.gnu.org/licenses/>.
 */

#include <config.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#include "agent.h"
#include "../common/i18n.h"
#include "../common/sysutils.h"


void
clear_ephemeral_keys (ctrl_t ctrl)
{
  while (ctrl->ephemeral_keys)
    {
      ephemeral_private_key_t next = ctrl->ephemeral_keys->next;
      if (ctrl->ephemeral_keys->keybuf)
        {
          wipememory (ctrl->ephemeral_keys->keybuf,
                      ctrl->ephemeral_keys->keybuflen);
          xfree (ctrl->ephemeral_keys->keybuf);
        }
      xfree (ctrl->ephemeral_keys);
      ctrl->ephemeral_keys = next;
    }
}


/* Store the key either to a file, or in ctrl->ephemeral_mode in the
 * session data.  */
static gpg_error_t
store_key (ctrl_t ctrl, gcry_sexp_t private,
           const char *passphrase, int force,
           unsigned long s2k_count, time_t timestamp)
{
  gpg_error_t err;
  unsigned char *buf;
  size_t len;
  unsigned char grip[KEYGRIP_LEN];

  if ( !gcry_pk_get_keygrip (private, grip) )
    {
      log_error ("can't calculate keygrip\n");
      return gpg_error (GPG_ERR_GENERAL);
    }

  len = gcry_sexp_sprint (private, GCRYSEXP_FMT_CANON, NULL, 0);
  log_assert (len);
  buf = gcry_malloc_secure (len);
  if (!buf)
    {
      err = gpg_error_from_syserror ();
      goto leave;
    }
  len = gcry_sexp_sprint (private, GCRYSEXP_FMT_CANON, buf, len);
  log_assert (len);

  if (passphrase)
    {
      unsigned char *p;

      err = agent_protect (buf, passphrase, &p, &len, s2k_count);
      if (err)
        goto leave;
      xfree (buf);
      buf = p;
    }

  if (ctrl->ephemeral_mode)
    {
      ephemeral_private_key_t ek;

      for (ek = ctrl->ephemeral_keys; ek; ek = ek->next)
        if (!memcmp (ek->grip, grip, KEYGRIP_LEN))
          break;
      if (!ek)
        {
          ek = xtrycalloc (1, sizeof *ek);
          if (!ek)
            {
              err = gpg_error_from_syserror ();
              goto leave;
            }
          memcpy (ek->grip, grip, KEYGRIP_LEN);
          ek->next = ctrl->ephemeral_keys;
          ctrl->ephemeral_keys = ek;
        }
      if (ek->keybuf)
        {
          wipememory (ek->keybuf, ek->keybuflen);
          xfree (ek->keybuf);
        }
      ek->keybuf = buf;
      buf = NULL;
      ek->keybuflen = len;
      err = 0;
    }
  else
    err = agent_write_private_key (ctrl, grip, buf, len, force,
                                   NULL, NULL, NULL, timestamp);

  if (!err)
    {
      char hexgrip[2*KEYGRIP_LEN+1];

      bin2hex (grip, KEYGRIP_LEN, hexgrip);
      agent_write_status (ctrl, "KEYGRIP", hexgrip, NULL);
    }

 leave:
  xfree (buf);
  return err;
}


/* Count the number of non-alpha characters in S.  Control characters
   and non-ascii characters are not considered.  */
static size_t
nonalpha_count (const char *s)
{
  size_t n;

  for (n=0; *s; s++)
    if (isascii (*s) && ( isdigit (*s) || ispunct (*s) ))
      n++;

  return n;
}


/* Check PW against a list of pattern.  Return 0 if PW does not match
   these pattern.  If CHECK_CONSTRAINTS_NEW_SYMKEY is set in flags and
   --check-sym-passphrase-pattern has been configured, use the pattern
   file from that option.  */
static int
do_check_passphrase_pattern (ctrl_t ctrl, const char *pw, unsigned int flags)
{
  gpg_error_t err = 0;
  const char *pgmname = gnupg_module_name (GNUPG_MODULE_NAME_CHECK_PATTERN);
  estream_t stream_to_check_pattern = NULL;
  const char *argv[10];
  gpgrt_process_t proc;
  int result, i;
  const char *pattern;
  char *patternfname;

  (void)ctrl;

  pattern = opt.check_passphrase_pattern;
  if ((flags & CHECK_CONSTRAINTS_NEW_SYMKEY)
      && opt.check_sym_passphrase_pattern)
    pattern = opt.check_sym_passphrase_pattern;
  if (!pattern)
    return 1; /* Oops - Assume password should not be used  */

  if (strchr (pattern, '/') || strchr (pattern, '\\')
      || (*pattern == '~' && pattern[1] == '/'))
    patternfname = make_absfilename_try (pattern, NULL);
  else
    patternfname = make_filename_try (gnupg_sysconfdir (), pattern, NULL);
  if (!patternfname)
    {
      log_error ("error making filename from '%s': %s\n",
                 pattern, gpg_strerror (gpg_error_from_syserror ()));
      return 1; /* Do not pass the check.  */
    }

  /* Make debugging a broken config easier by printing a useful error
   * message.  */
  if (gnupg_access (patternfname, F_OK))
    {
      log_error ("error accessing '%s': %s\n",
                 patternfname, gpg_strerror (gpg_error_from_syserror ()));
      xfree (patternfname);
      return 1; /* Do not pass the check.  */
    }

  i = 0;
  argv[i++] = "--null";
  argv[i++] = "--",
  argv[i++] = patternfname,
  argv[i] = NULL;
  log_assert (i < sizeof argv);

  if (gpgrt_process_spawn (pgmname, argv,
                           GPGRT_PROCESS_STDIN_PIPE,
                           NULL, &proc))
    result = 1; /* Execute error - assume password should no be used.  */
  else
    {
      int status;

      gpgrt_process_get_streams (proc, 0, &stream_to_check_pattern,
                                 NULL, NULL);

      es_set_binary (stream_to_check_pattern);
      if (es_fwrite (pw, strlen (pw), 1, stream_to_check_pattern) != 1)
        {
          err = gpg_error_from_syserror ();
          log_error (_("error writing to pipe: %s\n"), gpg_strerror (err));
          result = 1; /* Error - assume password should not be used.  */
        }
      else
        es_fflush (stream_to_check_pattern);
      es_fclose (stream_to_check_pattern);
      gpgrt_process_wait (proc, 1);
      gpgrt_process_ctl (proc, GPGRT_PROCESS_GET_EXIT_ID, &status);
      if (status)
        result = 1; /* Helper returned an error - probably a match.  */
      else
        result = 0; /* Success; i.e. no match.  */
      gpgrt_process_release (proc);
    }

  xfree (patternfname);
  return result;
}


static int
take_this_one_anyway (ctrl_t ctrl, const char *desc, const char *anyway_btn)
{
  return agent_get_confirmation (ctrl, desc,
                                 anyway_btn, L_("Enter new passphrase"), 0);
}


/* Check whether the passphrase PW is suitable. Returns 0 if the
 * passphrase is suitable and true if it is not and the user should be
 * asked to provide a different one.  If FAILED_CONSTRAINT is set, a
 * message describing the problem is returned at FAILED_CONSTRAINT.
 * The FLAGS are:
 *   CHECK_CONSTRAINTS_NOT_EMPTY
 *       Do not allow an empty passphrase
 *   CHECK_CONSTRAINTS_NEW_SYMKEY
 *       Hint that the passphrase is used for a new symmetric key.
 */
int
check_passphrase_constraints (ctrl_t ctrl, const char *pw, unsigned int flags,
			      char **failed_constraint)
{
  gpg_error_t err = 0;
  unsigned int minlen = opt.min_passphrase_len;
  unsigned int minnonalpha = opt.min_passphrase_nonalpha;
  char *msg1 = NULL;
  char *msg2 = NULL;
  char *msg3 = NULL;
  int no_empty = !!(flags & CHECK_CONSTRAINTS_NOT_EMPTY);

  if (ctrl && ctrl->pinentry_mode == PINENTRY_MODE_LOOPBACK)
    return 0;

  if (!pw)
    pw = "";

  /* The first check is to warn about an empty passphrase. */
  if (!*pw)
    {
      const char *desc = (opt.enforce_passphrase_constraints || no_empty?
                          L_("You have not entered a passphrase!%0A"
                             "An empty passphrase is not allowed.") :
                          L_("You have not entered a passphrase - "
                             "this is in general a bad idea!%0A"
                             "Please confirm that you do not want to "
                             "have any protection on your key."));

      err = 1;
      if (failed_constraint)
	{
	  if (opt.enforce_passphrase_constraints || no_empty)
	    *failed_constraint = xstrdup (desc);
	  else
	    err = take_this_one_anyway (ctrl, desc,
					L_("Yes, protection is not needed"));
	}

      goto leave;
    }

  /* Now check the constraints and collect the error messages unless
     in silent mode which returns immediately.  */
  if (utf8_charcount (pw, -1) < minlen )
    {
      if (!failed_constraint)
        {
          err = gpg_error (GPG_ERR_INV_PASSPHRASE);
          goto leave;
        }

      msg1 = xtryasprintf
        ( ngettext ("A passphrase should be at least %u character long.",
                    "A passphrase should be at least %u characters long.",
                    minlen), minlen );
      if (!msg1)
        {
          err = gpg_error_from_syserror ();
          goto leave;
        }
    }

  if (nonalpha_count (pw) < minnonalpha )
    {
      if (!failed_constraint)
        {
          err = gpg_error (GPG_ERR_INV_PASSPHRASE);
          goto leave;
        }

      msg2 = xtryasprintf
        ( ngettext ("A passphrase should contain at least %u digit or%%0A"
                    "special character.",
                    "A passphrase should contain at least %u digits or%%0A"
                    "special characters.",
                    minnonalpha), minnonalpha );
      if (!msg2)
        {
          err = gpg_error_from_syserror ();
          goto leave;
        }
    }

  /* If configured check the passphrase against a list of known words
     and pattern.  The actual test is done by an external program.
     The warning message is generic to give the user no hint on how to
     circumvent this list.  */
  if (*pw
      && (opt.check_passphrase_pattern || opt.check_sym_passphrase_pattern)
      && do_check_passphrase_pattern (ctrl, pw, flags))
    {
      if (!failed_constraint)
        {
          err = gpg_error (GPG_ERR_INV_PASSPHRASE);
          goto leave;
        }

      msg3 = xtryasprintf
        (L_("A passphrase may not be a known term or match%%0A"
            "certain pattern."));
      if (!msg3)
        {
          err = gpg_error_from_syserror ();
          goto leave;
        }
    }

  if (failed_constraint && (msg1 || msg2 || msg3))
    {
      char *msg;
      size_t n;

      msg = strconcat
        (L_("Warning: You have entered an insecure passphrase."),
         "%0A%0A",
         msg1? msg1 : "", msg1? "%0A" : "",
         msg2? msg2 : "", msg2? "%0A" : "",
         msg3? msg3 : "", msg3? "%0A" : "",
         NULL);
      if (!msg)
        {
          err = gpg_error_from_syserror ();
          goto leave;
        }
      /* Strip a trailing "%0A".  */
      n = strlen (msg);
      if (n > 3 && !strcmp (msg + n - 3, "%0A"))
        msg[n-3] = 0;

      err = 1;
      if (opt.enforce_passphrase_constraints)
	*failed_constraint = msg;
      else
	{
	  err = take_this_one_anyway (ctrl, msg, L_("Take this one anyway"));
	  xfree (msg);
	}
    }

 leave:
  xfree (msg1);
  xfree (msg2);
  xfree (msg3);
  return err;
}


/* Callback function to compare the first entered PIN with the one
   currently being entered. */
static gpg_error_t
reenter_compare_cb (struct pin_entry_info_s *pi)
{
  const char *pin1 = pi->check_cb_arg;

  if (!strcmp (pin1, pi->pin))
    return 0; /* okay */
  return gpg_error (GPG_ERR_BAD_PASSPHRASE);
}


/* Ask the user for a new passphrase using PROMPT.  On success the
   function returns 0 and store the passphrase at R_PASSPHRASE; if the
   user opted not to use a passphrase NULL will be stored there.  The
   user needs to free the returned string.  In case of an error and
   error code is returned and NULL stored at R_PASSPHRASE.  */
gpg_error_t
agent_ask_new_passphrase (ctrl_t ctrl, const char *prompt,
                          char **r_passphrase)
{
  gpg_error_t err;
  const char *text1 = prompt;
  const char *text2 = L_("Please re-enter this passphrase");
  char *initial_errtext = NULL;
  struct pin_entry_info_s *pi, *pi2;

  *r_passphrase = NULL;

  if (ctrl->pinentry_mode == PINENTRY_MODE_LOOPBACK)
    {
	size_t size;
	unsigned char *buffer;

	err = pinentry_loopback (ctrl, "NEW_PASSPHRASE", &buffer, &size,
                                 MAX_PASSPHRASE_LEN);
	if (!err)
	  {
	    if (size)
	      {
		buffer[size] = 0;
		*r_passphrase = buffer;
	      }
	    else
	        *r_passphrase = NULL;
	  }
	return err;
    }

  pi = gcry_calloc_secure (1, sizeof (*pi) + MAX_PASSPHRASE_LEN + 1);
  if (!pi)
    return gpg_error_from_syserror ();
  pi2 = gcry_calloc_secure (1, sizeof (*pi2) + MAX_PASSPHRASE_LEN + 1);
  if (!pi2)
    {
      err = gpg_error_from_syserror ();
      xfree (pi);
      return err;
    }
  pi->max_length = MAX_PASSPHRASE_LEN + 1;
  pi->max_tries = 3;
  pi->with_qualitybar = 0;
  pi->with_repeat = 1;
  pi2->max_length = MAX_PASSPHRASE_LEN + 1;
  pi2->max_tries = 3;
  pi2->check_cb = reenter_compare_cb;
  pi2->check_cb_arg = pi->pin;

 next_try:
  err = agent_askpin (ctrl, text1, NULL, initial_errtext, pi, NULL, 0);
  xfree (initial_errtext);
  initial_errtext = NULL;
  if (!err)
    {
      if (check_passphrase_constraints (ctrl, pi->pin, 0, &initial_errtext))
        {
          pi->failed_tries = 0;
          pi2->failed_tries = 0;
          goto next_try;
        }
      /* Unless the passphrase is empty or the pinentry told us that
         it already did the repetition check, ask to confirm it.  */
      if (*pi->pin && !pi->repeat_okay)
        {
          err = agent_askpin (ctrl, text2, NULL, NULL, pi2, NULL, 0);
          if (gpg_err_code (err) == GPG_ERR_BAD_PASSPHRASE)
            { /* The re-entered one did not match and the user did not
                 hit cancel. */
              initial_errtext = xtrystrdup (L_("does not match - try again"));
              if (initial_errtext)
                goto next_try;
              err = gpg_error_from_syserror ();
            }
        }
    }

  if (!err && *pi->pin)
    {
      /* User wants a passphrase. */
      *r_passphrase = xtrystrdup (pi->pin);
      if (!*r_passphrase)
        err = gpg_error_from_syserror ();
    }

  xfree (initial_errtext);
  xfree (pi2);
  xfree (pi);
  return err;
}



/* Generate a new keypair according to the parameters given in
 * KEYPARAM.  If CACHE_NONCE is given first try to lookup a passphrase
 * using the cache nonce.  If NO_PROTECTION is true the key will not
 * be protected by a passphrase.  If OVERRIDE_PASSPHRASE is true that
 * passphrase will be used for the new key.  If TIMESTAMP is not zero
 * it will be recorded as creation date of the key (unless extended
 * format is disabled).  In ctrl_ephemeral_mode the key is stored in
 * the session data and an identifier is returned using a status
 * line.  */
int
agent_genkey (ctrl_t ctrl, unsigned int flags,
              const char *cache_nonce, time_t timestamp,
              const char *keyparam, size_t keyparamlen,
              const char *override_passphrase, membuf_t *outbuf)
{
  gcry_sexp_t s_keyparam, s_key, s_private, s_public;
  char *passphrase_buffer = NULL;
  const char *passphrase;
  int rc;
  size_t len;
  char *buf;

  rc = gcry_sexp_sscan (&s_keyparam, NULL, keyparam, keyparamlen);
  if (rc)
    {
      log_error ("failed to convert keyparam: %s\n", gpg_strerror (rc));
      return gpg_error (GPG_ERR_INV_DATA);
    }

  /* Get the passphrase now, cause key generation may take a while. */
  if (override_passphrase)
    passphrase = override_passphrase;
  else if ((flags & GENKEY_FLAG_NO_PROTECTION) || !cache_nonce)
    passphrase = NULL;
  else
    {
      passphrase_buffer = agent_get_cache (ctrl, cache_nonce, CACHE_MODE_NONCE);
      passphrase = passphrase_buffer;
    }

  if (passphrase || (flags & GENKEY_FLAG_NO_PROTECTION))
    ; /* No need to ask for a passphrase.  */
  else
    {
      rc = agent_ask_new_passphrase (ctrl,
                                     L_("Please enter the passphrase to%0A"
                                        "protect your new key"),
                                     &passphrase_buffer);
      if (rc)
        {
          gcry_sexp_release (s_keyparam);
          return rc;
        }
      passphrase = passphrase_buffer;
    }

  rc = gcry_pk_genkey (&s_key, s_keyparam );
  gcry_sexp_release (s_keyparam);
  if (rc)
    {
      log_error ("key generation failed: %s\n", gpg_strerror (rc));
      xfree (passphrase_buffer);
      return rc;
    }

  /* break out the parts */
  s_private = gcry_sexp_find_token (s_key, "private-key", 0);
  if (!s_private)
    {
      log_error ("key generation failed: invalid return value\n");
      gcry_sexp_release (s_key);
      xfree (passphrase_buffer);
      return gpg_error (GPG_ERR_INV_DATA);
    }
  s_public = gcry_sexp_find_token (s_key, "public-key", 0);
  if (!s_public)
    {
      log_error ("key generation failed: invalid return value\n");
      gcry_sexp_release (s_private);
      gcry_sexp_release (s_key);
      xfree (passphrase_buffer);
      return gpg_error (GPG_ERR_INV_DATA);
    }

  /* libgcrypt prior to 1.10 does not include the (q ...) field for
     GOST keys.  Fix this up by computing Q from the secret key.  */
  {
    gcry_sexp_t ecc, ecc_priv, flags = NULL, newpub = NULL;
    gcry_mpi_t qmpi = NULL, dmpi = NULL;
    char *curve = NULL;
    gcry_ctx_t ctx;

    ecc = gcry_sexp_find_token (s_public, "ecc", 0);
    if (ecc && !gcry_sexp_find_token (ecc, "q", 0))
      {
        flags = gcry_sexp_find_token (ecc, "flags", 0);
        ecc_priv = gcry_sexp_find_token (s_private, "ecc", 0);
        if (ecc_priv)
          {
            gcry_sexp_t tmp;

            tmp = gcry_sexp_find_token (ecc_priv, "q", 0);
            if (tmp)
              {
                qmpi = gcry_sexp_nth_mpi (tmp, 1, GCRYMPI_FMT_USG);
                gcry_sexp_release (tmp);
              }
            tmp = gcry_sexp_find_token (ecc_priv, "d", 0);
            if (tmp)
              {
                dmpi = gcry_sexp_nth_mpi (tmp, 1, GCRYMPI_FMT_USG);
                gcry_sexp_release (tmp);
              }
            gcry_sexp_release (ecc_priv);
          }

        if (!curve)
          {
            gcry_sexp_t tmp = gcry_sexp_find_token (ecc, "curve", 0);
            if (tmp)
              {
                curve = gcry_sexp_nth_string (tmp, 1);
                gcry_sexp_release (tmp);
              }
          }

        if (!qmpi && curve && dmpi &&
            !gcry_mpi_ec_new (&ctx, NULL, curve))
          {
            if (!gcry_mpi_ec_set_mpi ("d", dmpi, ctx))
              qmpi = gcry_mpi_ec_get_mpi ("q", ctx, 1);
            gcry_ctx_release (ctx);
          }

        if (qmpi && curve)
          {
            if (flags)
              gcry_sexp_build (&newpub, NULL,
                               "(public-key(ecc(curve %s)%S(q%m)))",
                               curve, flags, qmpi);
            else
              gcry_sexp_build (&newpub, NULL,
                               "(public-key(ecc(curve %s)(q%m)))",
                               curve, qmpi);
          }

        if (newpub)
          {
            gcry_sexp_release (s_public);
            s_public = newpub;
          }

        xfree (curve);
        gcry_mpi_release (qmpi);
        gcry_mpi_release (dmpi);
        if (flags)
          gcry_sexp_release (flags);
      }
    if (ecc)
      gcry_sexp_release (ecc);
  }
  gcry_sexp_release (s_key); s_key = NULL;

  /* store the secret key */
  if (opt.verbose)
    log_info ("storing %sprivate key\n",
               ctrl->ephemeral_mode?"ephemeral ":"");
  rc = store_key (ctrl, s_private, passphrase, 0, ctrl->s2k_count, timestamp);
  if (!rc && !ctrl->ephemeral_mode)
    {
      /* FIXME: or does it make sense to also cache passphrases in
       * ephemeral mode using a dedicated cache?  */
      if (!cache_nonce)
        {
          char tmpbuf[12];
          gcry_create_nonce (tmpbuf, 12);
          cache_nonce = bin2hex (tmpbuf, 12, NULL);
        }
      if (cache_nonce
          && !(flags & GENKEY_FLAG_NO_PROTECTION)
          && !agent_put_cache (ctrl, cache_nonce, CACHE_MODE_NONCE,
                               passphrase, ctrl->cache_ttl_opt_preset))
        agent_write_status (ctrl, "CACHE_NONCE", cache_nonce, NULL);
      if ((flags & GENKEY_FLAG_PRESET)
          && !(flags & GENKEY_FLAG_NO_PROTECTION))
        {
          unsigned char grip[20];
          char hexgrip[40+1];
          if (gcry_pk_get_keygrip (s_private, grip))
            {
              bin2hex(grip, 20, hexgrip);
              rc = agent_put_cache (ctrl, hexgrip,
                                    CACHE_MODE_ANY, passphrase,
                                    ctrl->cache_ttl_opt_preset);
            }
        }
    }
  xfree (passphrase_buffer);
  passphrase_buffer = NULL;
  passphrase = NULL;
  gcry_sexp_release (s_private);
  if (rc)
    {
      gcry_sexp_release (s_public);
      return rc;
    }

  /* return the public key */
  if (DBG_CRYPTO)
    log_debug ("returning public key\n");
  len = gcry_sexp_sprint (s_public, GCRYSEXP_FMT_CANON, NULL, 0);
  log_assert (len);
  buf = xtrymalloc (len);
  if (!buf)
    {
      gpg_error_t tmperr = out_of_core ();
      gcry_sexp_release (s_private);
      gcry_sexp_release (s_public);
      return tmperr;
    }
  len = gcry_sexp_sprint (s_public, GCRYSEXP_FMT_CANON, buf, len);
  log_assert (len);
  put_membuf (outbuf, buf, len);
  gcry_sexp_release (s_public);
  xfree (buf);

  return 0;
}



/* Apply a new passphrase to the key S_SKEY and store it.  If
   PASSPHRASE_ADDR and *PASSPHRASE_ADDR are not NULL, use that
   passphrase.  If PASSPHRASE_ADDR is not NULL store a newly entered
   passphrase at that address. */
gpg_error_t
agent_protect_and_store (ctrl_t ctrl, gcry_sexp_t s_skey,
                         char **passphrase_addr)
{
  gpg_error_t err;

  if (passphrase_addr && *passphrase_addr)
    {
      /* Take an empty string as request not to protect the key.  */
      err = store_key (ctrl, s_skey,
                       **passphrase_addr? *passphrase_addr:NULL, 1,
                       ctrl->s2k_count, 0);
    }
  else
    {
      char *pass = NULL;

      if (passphrase_addr)
        {
          xfree (*passphrase_addr);
          *passphrase_addr = NULL;
        }
      err = agent_ask_new_passphrase (ctrl,
                                      L_("Please enter the new passphrase"),
                                      &pass);
      if (!err)
        err = store_key (ctrl, s_skey, pass, 1, ctrl->s2k_count, 0);
      if (!err && passphrase_addr)
        *passphrase_addr = pass;
      else
        xfree (pass);
    }

  return err;
}
