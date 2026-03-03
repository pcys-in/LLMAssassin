# LLMAssassin - SpamAssassin plugin for AI-powered spam detection
# Uses any OpenAI-compatible API (OpenAI, Azure, local Ollama, etc.)
#
# Copyright (C) 2026 Albus / Patronum
# Licensed under the Apache License 2.0
#
# https://github.com/patronum/LLMAssassin

package Mail::SpamAssassin::Plugin::LLMAssassin;

use strict;
use warnings;

use Mail::SpamAssassin::Plugin;
use Mail::SpamAssassin::Logger;

our @ISA = qw(Mail::SpamAssassin::Plugin);

# ── Defaults ──────────────────────────────────────────────────────────────────
use constant {
    DEF_API_BASE           => 'https://api.openai.com',
    DEF_API_KEY            => '',
    DEF_MODEL              => 'gpt-4.1',
    DEF_TIMEOUT            => 15,
    DEF_SPAM_SCORE         => 6.0,
    DEF_FAIL_SCORE         => 0.0,
    DEF_FAIL_CLOSED        => 0,       # 0 = fail open, 1 = fail closed
    DEF_MAX_BODY_CHARS     => 8000,
    DEF_MAX_CALLS_PER_MIN  => 0,       # 0 = unlimited
    DEF_DRY_RUN            => 0,       # 0 = live, 1 = log only, never score
    DEF_SKIP_AUTHENTICATED => 0,       # 1 = skip AI for SMTP-auth'd senders
    DEF_SCORE_MAP          => '',      # e.g. "0.9-1.0=8.0,0.7-0.9=5.0,0.5-0.7=2.0"
    DEF_RATE_FILE          => '/tmp/llmassassin.rate',
    DEF_DEBUG              => 0,       # 1 = verbose step-by-step logging
    DEF_SEND_SA_SIGNALS    => 1,       # 0 = omit SA score/bayes/rules from prompt
    DEF_REWRITE_SUBJECT    => 1,       # 1 = prepend [LLMAssassin: reason] to Subject when spam
    DEF_SYSTEM_PROMPT      =>
        'You are an expert email spam classifier. ' .
        'Analyse the email data provided — including headers, authentication results, ' .
        'SpamAssassin content signals, URLs, attachments, and body text. ' .
        'IMPORTANT: A valid DKIM signature, passing SPF, or good sender reputation does NOT mean an email is not spam. ' .
        'Many bulk marketing, phishing, and unsolicited commercial emails are sent from authenticated infrastructure. ' .
        'Judge primarily on the CONTENT and INTENT of the email, not on authentication results. ' .
        'Reply with EXACTLY one JSON object and nothing else: ' .
        '{"spam": true/false, "confidence": 0.0-1.0, "reason": "<concise reason, max 8 words>"}',
};

# ── Constructor ───────────────────────────────────────────────────────────────
sub new {
    my ($class, $mailsa) = @_;
    my $self = $class->SUPER::new($mailsa);

    $self->register_eval_rule('check_llm_spam');
    $self->set_config($mailsa->{conf});

    return $self;
}

# ── Config declarations ───────────────────────────────────────────────────────
sub set_config {
    my ($self, $conf) = @_;
    my @cmds = (
        {
            setting => 'llm_api_base',
            default => DEF_API_BASE,
            type    => $Mail::SpamAssassin::Conf::CONF_TYPE_STRING,
        },
        {
            setting => 'llm_api_key',
            default => DEF_API_KEY,
            type    => $Mail::SpamAssassin::Conf::CONF_TYPE_STRING,
        },
        {
            setting => 'llm_model',
            default => DEF_MODEL,
            type    => $Mail::SpamAssassin::Conf::CONF_TYPE_STRING,
        },
        {
            setting => 'llm_timeout',
            default => DEF_TIMEOUT,
            type    => $Mail::SpamAssassin::Conf::CONF_TYPE_NUMERIC,
        },
        {
            setting => 'llm_spam_score',
            default => DEF_SPAM_SCORE,
            type    => $Mail::SpamAssassin::Conf::CONF_TYPE_NUMERIC,
        },
        {
            setting => 'llm_fail_closed',
            default => DEF_FAIL_CLOSED,
            type    => $Mail::SpamAssassin::Conf::CONF_TYPE_NUMERIC,
        },
        {
            setting => 'llm_fail_score',
            default => DEF_FAIL_SCORE,
            type    => $Mail::SpamAssassin::Conf::CONF_TYPE_NUMERIC,
        },
        {
            setting => 'llm_max_body_chars',
            default => DEF_MAX_BODY_CHARS,
            type    => $Mail::SpamAssassin::Conf::CONF_TYPE_NUMERIC,
        },
        {
            setting => 'llm_max_calls_per_minute',
            default => DEF_MAX_CALLS_PER_MIN,
            type    => $Mail::SpamAssassin::Conf::CONF_TYPE_NUMERIC,
        },
        {
            setting => 'llm_dry_run',
            default => DEF_DRY_RUN,
            type    => $Mail::SpamAssassin::Conf::CONF_TYPE_NUMERIC,
        },
        {
            setting => 'llm_skip_authenticated',
            default => DEF_SKIP_AUTHENTICATED,
            type    => $Mail::SpamAssassin::Conf::CONF_TYPE_NUMERIC,
        },
        {
            setting => 'llm_score_map',
            default => DEF_SCORE_MAP,
            type    => $Mail::SpamAssassin::Conf::CONF_TYPE_STRING,
        },
        {
            setting => 'llm_system_prompt',
            default => DEF_SYSTEM_PROMPT,
            type    => $Mail::SpamAssassin::Conf::CONF_TYPE_STRING,
        },
        {
            setting => 'llm_rate_file',
            default => DEF_RATE_FILE,
            type    => $Mail::SpamAssassin::Conf::CONF_TYPE_STRING,
        },
        {
            setting => 'llm_debug',
            default => DEF_DEBUG,
            type    => $Mail::SpamAssassin::Conf::CONF_TYPE_NUMERIC,
        },
        {
            # 1 = prepend [LLMAssassin: reason] to Subject header when spam detected
            setting => 'llm_rewrite_subject',
            default => DEF_REWRITE_SUBJECT,
            type    => $Mail::SpamAssassin::Conf::CONF_TYPE_NUMERIC,
        },
        {
            # 0 = omit SA score, Bayes probability and fired rules from the prompt
            setting => 'llm_send_sa_signals',
            default => DEF_SEND_SA_SIGNALS,
            type    => $Mail::SpamAssassin::Conf::CONF_TYPE_NUMERIC,
        },
    );
    $conf->{parser}->register_commands(\@cmds);
}

# ── Debug helper — only logs when llm_debug = 1 ───────────────────────────────
# Uses two-argument dbg() so SA's -D llmassassin channel filter picks it up.
sub _dbgv {
    my ($debug, $msg) = @_;
    return unless $debug;
    dbg("LLMAssassin: $msg");
}

# ── Main eval rule ────────────────────────────────────────────────────────────
sub check_llm_spam {
    my ($self, $pms) = @_;

    my $conf      = $pms->{conf};
    my $debug     = $conf->{llm_debug}             // DEF_DEBUG;
    my $dry_run   = $conf->{llm_dry_run}            // DEF_DRY_RUN;
    my $skip_auth = $conf->{llm_skip_authenticated} // DEF_SKIP_AUTHENTICATED;
    my $max_calls = $conf->{llm_max_calls_per_minute} // DEF_MAX_CALLS_PER_MIN;
    my $fail_closed = $conf->{llm_fail_closed}      // DEF_FAIL_CLOSED;
    my $score_map = $conf->{llm_score_map}          // DEF_SCORE_MAP;

    if ($debug) {
        my $safe_base = $conf->{llm_api_base} // DEF_API_BASE;
        $safe_base =~ s{(https?://)([^:@/]+):([^@/]+)@}{$1$2:***@}i;
        my $has_key = ($conf->{llm_api_key} // '') ne '' ? 'yes' : 'no';

        dbg("LLMAssassin: ============================================================");
        dbg("LLMAssassin: RUNNING IN DEBUG MODE");
        dbg("LLMAssassin: ============================================================");
        dbg("LLMAssassin: VARS SET:");
        dbg("LLMAssassin:   llm_api_base             = $safe_base");
        dbg("LLMAssassin:   llm_api_key set          = $has_key");
        dbg("LLMAssassin:   llm_model                = " . ($conf->{llm_model}         // DEF_MODEL));
        dbg("LLMAssassin:   llm_timeout              = " . ($conf->{llm_timeout}        // DEF_TIMEOUT));
        dbg("LLMAssassin:   llm_spam_score           = " . ($conf->{llm_spam_score}     // DEF_SPAM_SCORE));
        dbg("LLMAssassin:   llm_score_map            = " . ($score_map ne '' ? $score_map : '(not set, using flat score)'));
        dbg("LLMAssassin:   llm_fail_closed          = $fail_closed");
        dbg("LLMAssassin:   llm_fail_score           = " . ($conf->{llm_fail_score}     // DEF_FAIL_SCORE));
        dbg("LLMAssassin:   llm_dry_run              = $dry_run");
        dbg("LLMAssassin:   llm_skip_authenticated   = $skip_auth");
        dbg("LLMAssassin:   llm_max_calls_per_minute = $max_calls");
        dbg("LLMAssassin:   llm_max_body_chars       = " . ($conf->{llm_max_body_chars} // DEF_MAX_BODY_CHARS));
        dbg("LLMAssassin:   llm_rate_file            = " . ($conf->{llm_rate_file}      // DEF_RATE_FILE));
        dbg("LLMAssassin:   llm_rewrite_subject      = " . ($conf->{llm_rewrite_subject} // DEF_REWRITE_SUBJECT));
        dbg("LLMAssassin:   llm_send_sa_signals      = " . ($conf->{llm_send_sa_signals} // DEF_SEND_SA_SIGNALS));
        dbg("LLMAssassin: ============================================================");
    }

    # ── Step 1: Skip authenticated senders ───────────────────────────────────
    _dbgv($debug, "STEP 1: Checking if sender is SMTP-authenticated (llm_skip_authenticated=$skip_auth)");
    if ($skip_auth) {
        my $auth_sender = $pms->get('X-Authenticated-Sender');
        _dbgv($debug, "  X-Authenticated-Sender header: " . ($auth_sender ne '' ? $auth_sender : '(not present)'));
        if ($auth_sender ne '') {
            _dbgv($debug, "  => Sender is authenticated. Skipping AI check.");
            dbg("LLMAssassin: skipping — sender is SMTP-authenticated");
            return 0;
        }
    }
    _dbgv($debug, "  => Not skipping on auth.");

    # ── Step 2: Check SA whitelist ────────────────────────────────────────────
    _dbgv($debug, "STEP 2: Checking SA whitelists (whitelist_from, whitelist_auth, def_whitelist_from)");
    my $sender = $pms->get('From:addr');
    chomp $sender;
    _dbgv($debug, "  Envelope sender: $sender");
    if (_is_whitelisted($pms)) {
        _dbgv($debug, "  => Sender matches SA whitelist. Skipping AI check.");
        dbg("LLMAssassin: skipping — sender matches SA whitelist");
        return 0;
    }
    _dbgv($debug, "  => Sender not whitelisted. Continuing.");

    # ── Step 3: Rate limiting ─────────────────────────────────────────────────
    _dbgv($debug, "STEP 3: Rate limiting (max=$max_calls calls/min, 0=unlimited)");
    if ($max_calls > 0) {
        if (!$self->_check_rate_limit($conf, $max_calls)) {
            _dbgv($debug, "  => Rate limit of $max_calls/min reached.");
            dbg("LLMAssassin: rate limit reached ($max_calls/min)");
            if ($fail_closed) {
                my $fail_score = $conf->{llm_fail_score} // DEF_FAIL_SCORE;
                _dbgv($debug, "  => fail_closed=1, applying fail_score=$fail_score");
                $pms->set_tag('LLMSPAMREASON', 'Rate limited');
                return $dry_run ? 0 : ($fail_score > 0 ? 1 : 0);
            }
            _dbgv($debug, "  => fail_closed=0, scoring 0 and passing through.");
            return 0;
        }
        _dbgv($debug, "  => Under rate limit. Allowed.");
    } else {
        _dbgv($debug, "  => Rate limiting disabled.");
    }

    # ── Step 4: Build prompt content ─────────────────────────────────────────
    _dbgv($debug, "STEP 4: Building prompt content (headers, auth, SA signals, URLs, attachments, body)");
    _dbgv($debug, "  llm_send_sa_signals=" . ($conf->{llm_send_sa_signals} // DEF_SEND_SA_SIGNALS) . " — " . (($conf->{llm_send_sa_signals} // DEF_SEND_SA_SIGNALS) ? "SA score/bayes/rules WILL be included in prompt" : "SA score/bayes/rules WILL NOT be included in prompt"));
    my $email_content = _build_prompt_content($pms, $conf);
    _dbgv($debug, "  => Prompt content built. Total length: " . length($email_content) . " chars");

    # ── Step 5: Call the AI ───────────────────────────────────────────────────
    _dbgv($debug, "STEP 5: Calling AI API");
    _dbgv($debug, "  Prompt being sent to AI:");
    _dbgv($debug, "  ---- PROMPT START ----");
    for my $line (split /\n/, $email_content) {
        dbg("LLMAssassin:   $line");
    }
    _dbgv($debug, "  ---- PROMPT END ----");
    my ($is_spam, $confidence, $reason) = $self->_call_ai($conf, $email_content, $debug);

    # ── Step 6: Handle API failure ────────────────────────────────────────────
    _dbgv($debug, "STEP 6: Handling API response");
    if (!defined $is_spam) {
        _dbgv($debug, "  => API call returned undef (failed or timed out)");
        _dbgv($debug, "  => fail_closed=$fail_closed");
        dbg("LLMAssassin: API failed, fail_closed=$fail_closed");
        $pms->set_tag('LLMSPAMREASON', 'AI check error');
        if ($fail_closed) {
            _dbgv($debug, "  => Returning 1 (fail closed). dry_run=$dry_run — " . ($dry_run ? "dry_run active, returning 0 instead" : "scoring"));
            return $dry_run ? 0 : 1;
        }
        _dbgv($debug, "  => Returning 0 (fail open).");
        return 0;
    }

    _dbgv($debug, "  => API returned: spam=$is_spam confidence=$confidence reason=$reason");

    # ── Step 7: Tag the message ───────────────────────────────────────────────
    my $conf_pct = int($confidence * 100);
    _dbgv($debug, "STEP 7: Setting SA tags — LLMSPAMREASON='$reason' LLMSPAMCONFIDENCE='${conf_pct}%'");
    $pms->set_tag('LLMSPAMREASON',     $reason);
    $pms->set_tag('LLMSPAMCONFIDENCE', $conf_pct . '%');

    dbg("LLMAssassin: spam=$is_spam confidence=$confidence reason=$reason dry_run=$dry_run");

    if (!$is_spam) {
        _dbgv($debug, "STEP 8: Not spam. Returning 0.");
        return 0;
    }

    if ($dry_run) {
        _dbgv($debug, "STEP 8: IS SPAM but dry_run=1 — not scoring. Returning 0.");
        return 0;
    }

    # ── Step 8: Apply score map ───────────────────────────────────────────────
    _dbgv($debug, "STEP 8: IS SPAM. Applying score.");
    if ($score_map) {
        _dbgv($debug, "  => score_map is set: '$score_map'");
        _dbgv($debug, "  => Looking up confidence=$confidence in map");
        my $mapped = _apply_score_map($score_map, $confidence);
        if (defined $mapped) {
            _dbgv($debug, "  => Mapped score: $mapped — overriding LLM_SPAM_CHECK score");
            $pms->{conf}->{scores}->{'LLM_SPAM_CHECK'} = $mapped;
            dbg("LLMAssassin: score_map applied — confidence=$confidence score=$mapped");
        } else {
            _dbgv($debug, "  => confidence=$confidence did not match any range in score_map. Using flat llm_spam_score.");
        }
    } else {
        _dbgv($debug, "  => No score_map set. Using flat llm_spam_score=" . ($conf->{llm_spam_score} // DEF_SPAM_SCORE));
    }

    # ── Rewrite Subject header ───────────────────────────────────────────────
    my $rewrite_subj = $conf->{llm_rewrite_subject} // DEF_REWRITE_SUBJECT;
    if ($rewrite_subj && !$dry_run) {
        my $current_subject = $pms->get('Subject') // '';
        chomp $current_subject;
        unless ($current_subject =~ /^\[LLMAssassin:/i) {
            my $new_subject = "[LLMAssassin: $reason] $current_subject";
            # SA stores parsed headers in {headers} as { lc_name => [values] }
            # and the raw header array in {header} as ["Name: Value\n", ...]
            # We update both so all downstream access sees the new value.
            eval {
                # Update parsed header hash
                $pms->{msg}->{headers}->{'subject'} = [$new_subject]
                    if ref $pms->{msg}->{headers} eq 'HASH';

                # Update raw header array
                if (ref $pms->{msg}->{header} eq 'ARRAY') {
                    @{$pms->{msg}->{header}} =
                        grep { !/^Subject\s*:/i } @{$pms->{msg}->{header}};
                    push @{$pms->{msg}->{header}}, "Subject: $new_subject\n";
                }
            };
            if ($@) {
                dbg("LLMAssassin: subject rewrite failed: $@");
            } else {
                _dbgv($debug, "STEP 9: Subject rewritten to: $new_subject");
            }
            _dbgv($debug, "STEP 9: Subject rewritten to: $new_subject");
        } else {
            _dbgv($debug, "STEP 9: Subject already tagged, skipping rewrite.");
        }
    } elsif (!$rewrite_subj) {
        _dbgv($debug, "STEP 9: llm_rewrite_subject=0, not rewriting Subject.");
    }

    _dbgv($debug, "STEP 10: Returning 1 — message will be scored as spam.");
    dbg("LLMAssassin: ============================================================");

    return 1;
}

# ── Check SA whitelists ───────────────────────────────────────────────────────
sub _is_whitelisted {
    my ($pms) = @_;
    my $conf   = $pms->{conf};
    my $sender = $pms->get('From:addr');
    chomp $sender;

    for my $wl_ref (
        $conf->{whitelist_from},
        $conf->{whitelist_auth},
        $conf->{def_whitelist_from},
    ) {
        next unless ref $wl_ref eq 'HASH';
        for my $entry (keys %$wl_ref) {
            my $pattern = $entry;
            $pattern =~ s/\./\\./g;
            $pattern =~ s/\*/.*/g;
            return 1 if $sender =~ /^$pattern$/i;
        }
    }
    return 0;
}

# ── Build full prompt content ─────────────────────────────────────────────────
sub _build_prompt_content {
    my ($pms, $conf) = @_;
    my $max_chars = $conf->{llm_max_body_chars} // DEF_MAX_BODY_CHARS;
    my $content   = '';

    $content .= "=== EMAIL HEADERS ===\n";
    for my $h (qw(
        From To Cc Reply-To Subject Date Message-ID
        X-Mailer User-Agent MIME-Version Content-Type
        X-Originating-IP X-Forwarded-To List-Unsubscribe Precedence
    )) {
        my $val = $pms->get($h);
        next unless defined $val && $val ne '';
        $content .= "$h: $val\n";
    }

    $content .= "\n=== RECEIVED CHAIN ===\n";
    my @received = $pms->get('Received');
    $content .= join('', @received) if @received;

    $content .= "\n=== AUTHENTICATION ===\n";
    for my $h (qw(
        Authentication-Results DKIM-Signature Received-SPF
        X-Google-DKIM-Signature ARC-Authentication-Results
    )) {
        my $val = $pms->get($h);
        next unless defined $val && $val ne '';
        $content .= "$h: $val\n";
    }

    my $send_sa = $conf->{llm_send_sa_signals} // DEF_SEND_SA_SIGNALS;
    if ($send_sa) {
        # ── Only send content-relevant SA signals to the LLM ─────────────────
        # Authentication signals (DKIM, SPF, IP reputation, whitelists) are
        # already visible in the raw headers above — sending them again as a
        # numeric score causes the LLM to over-weight auth reputation and ignore
        # content. We filter them out and only pass signals that reflect the
        # actual content and structure of the email.
        my @auth_prefixes = qw(
            DKIM DMARC SPF ARC
            RCVD_IN USER_IN DEF_
            MSPIKE VALIDITY DNSWL
            KHOP_ RDNS_ RELAYCOUNTRY
            NO_RELAYS NO_RECEIVED
        );
        my @content_rules;
        for my $rule (sort keys %{ $pms->{test_log_msgs} // {} }) {
            next unless $pms->get_score($rule) != 0;
            my $is_auth = 0;
            for my $pfx (@auth_prefixes) {
                if (index(uc($rule), uc($pfx)) == 0) { $is_auth = 1; last }
            }
            push @content_rules, $rule unless $is_auth;
        }

        if (@content_rules || $pms->get_tag('BAYESSCORE')) {
            $content .= "\n=== SPAMASSASSIN CONTENT SIGNALS ===\n";
            $content .= "(Authentication/reputation signals omitted — see headers above)\n";

            my $bayes = $pms->get_tag('BAYESSCORE');
            $content .= "Bayes spam probability: $bayes\n" if defined $bayes && $bayes ne '';

            if (@content_rules) {
                $content .= "Content rules fired: " . join(', ', @content_rules) . "\n";
            } else {
                $content .= "Content rules fired: none\n";
            }
        }
    }

    $content .= "\n=== URLS FOUND IN EMAIL ===\n";
    my @uris = $pms->get_uri_list();
    $content .= @uris ? join("\n", @uris) . "\n" : "None\n";

    $content .= "\n=== ATTACHMENTS ===\n";
    my $msg       = $pms->{msg};
    my @all_parts = $msg->find_parts(qr/./, 1);
    my @attachments;
    for my $part (@all_parts) {
        my $ct = $part->get_header('content-type')        // '';
        my $cd = $part->get_header('content-disposition') // '';
        if ($cd =~ /attachment/i || $ct =~ /application|image|audio|video/i) {
            my ($filename) = $cd =~ /filename="?([^";]+)"?/i;
            $filename //= 'unnamed';
            $ct =~ s/\s+/ /g;
            push @attachments, "  - $filename ($ct)";
        }
    }
    $content .= @attachments ? join("\n", @attachments) . "\n" : "None\n";

    $content .= "\n=== BODY ===\n";
    my $body  = '';
    my @parts = $msg->find_parts(qr/text\/plain/i);
    @parts    = $msg->find_parts(qr/./) unless @parts;
    for my $part (@parts) {
        my $decoded = $part->decode();
        next unless defined $decoded;
        $body .= $decoded;
        last if length($body) > $max_chars * 2;
    }
    $body     = substr($body, 0, $max_chars) if length($body) > $max_chars;
    $content .= $body . "\n";

    return $content;
}

# ── Apply confidence → score map ──────────────────────────────────────────────
sub _apply_score_map {
    my ($map_str, $confidence) = @_;
    for my $entry (split /,/, $map_str) {
        $entry = _trim($entry);
        if ($entry =~ /^([\d.]+)-([\d.]+)=([\d.]+)$/) {
            my ($low, $high, $score) = ($1+0, $2+0, $3+0);
            return $score if $confidence >= $low && $confidence <= $high;
        }
    }
    return undef;
}

# ── Rate limiter ──────────────────────────────────────────────────────────────
sub _check_rate_limit {
    my ($self, $conf, $max_calls) = @_;
    my $rate_file = $conf->{llm_rate_file} // DEF_RATE_FILE;
    my $now       = time();

    my @timestamps;
    if (open my $fh, '<', $rate_file) {
        @timestamps = map { chomp; $_ + 0 } <$fh>;
        close $fh;
    }

    @timestamps = grep { $now - $_ < 60 } @timestamps;
    return 0 if scalar(@timestamps) >= $max_calls;

    push @timestamps, $now;
    if (open my $fh, '>', $rate_file) {
        print $fh "$_\n" for @timestamps;
        close $fh;
    }

    return 1;
}

# ── Call OpenAI-compatible API ────────────────────────────────────────────────
sub _call_ai {
    my ($self, $conf, $content, $debug) = @_;
    $debug //= 0;

    my $api_base      = $conf->{llm_api_base}     // DEF_API_BASE;
    my $api_key       = $conf->{llm_api_key}       // DEF_API_KEY;
    my $model         = $conf->{llm_model}         // DEF_MODEL;
    my $timeout       = $conf->{llm_timeout}       // DEF_TIMEOUT;
    my $system_prompt = $conf->{llm_system_prompt} // DEF_SYSTEM_PROMPT;

    # ── Untaint ───────────────────────────────────────────────────────────────
    _dbgv($debug, "  [_call_ai] Untainting config values...");

    my ($url_user, $url_pass, $clean_base);
    if ($api_base =~ m{^(https?://)([^/:@]+):([^@]+)@(.+)$}i) {
        my ($scheme, $user, $pass, $host) = ($1, $2, $3, $4);
        _dbgv($debug, "  [_call_ai] URL contains embedded credentials — extracting user:pass");
        ($url_user) = ($user =~ /^([\w\-._~%!$&'()*+,;=]+)$/) or do {
            _dbgv($debug, "  [_call_ai] ERROR: username failed taint check");
            dbg("LLMAssassin: username in llm_api_base failed taint check");
            return (undef, undef, undef);
        };
        ($url_pass) = ($pass =~ /^([\w\-._~%!$&'()*+,;=\@]+)$/) or do {
            _dbgv($debug, "  [_call_ai] ERROR: password failed taint check");
            dbg("LLMAssassin: password in llm_api_base failed taint check");
            return (undef, undef, undef);
        };
        ($clean_base) = ("${scheme}${host}" =~ /^(https?:\/\/[^\s]+)$/i) or do {
            _dbgv($debug, "  [_call_ai] ERROR: host failed taint check");
            dbg("LLMAssassin: host in llm_api_base failed taint check");
            return (undef, undef, undef);
        };
        _dbgv($debug, "  [_call_ai] Credentials extracted OK. User: $url_user Pass: ***");
    } else {
        _dbgv($debug, "  [_call_ai] No embedded credentials in URL");
        ($clean_base) = ($api_base =~ /^(https?:\/\/[^\s]+)$/i) or do {
            _dbgv($debug, "  [_call_ai] ERROR: llm_api_base failed taint check: $api_base");
            dbg("LLMAssassin: llm_api_base failed taint check: $api_base");
            return (undef, undef, undef);
        };
    }

    ($api_key)  = ($api_key =~ /^([\w\-._~+\/=]*)$/) if $api_key;
    ($model)    = ($model   =~ /^([\w\-.:]+)$/) or do {
        _dbgv($debug, "  [_call_ai] ERROR: model failed taint check: $model");
        dbg("LLMAssassin: llm_model failed taint check: $model");
        return (undef, undef, undef);
    };
    ($timeout) = ($timeout =~ /^(\d+)$/);
    $timeout //= DEF_TIMEOUT;

    $clean_base =~ s|/+$||;
    my $url = "$clean_base/v1/chat/completions";

    _dbgv($debug, "  [_call_ai] Taint checks passed.");

    # ── Build payload ─────────────────────────────────────────────────────────
    my $payload = _json_encode({
        model       => $model,
        temperature => 0,
        max_tokens  => 100,
        messages    => [
            { role => 'system', content => $system_prompt },
            { role => 'user',   content => $content       },
        ],
    });

    if ($debug) {
        my $safe_url = $url;
        $safe_url =~ s{(https?://)([^:@/]+):([^@/]+)@}{$1$2:***@}i;
        my $safe_key = $api_key ? substr($api_key, 0, 6) . '***' : '(none)';
        _dbgv($debug, "  [_call_ai] Sending request:");
        _dbgv($debug, "    URL:            $safe_url");
        _dbgv($debug, "    Model:          $model");
        _dbgv($debug, "    Auth:           " . ($api_key ? "Bearer $safe_key" : ($url_user ? "Basic $url_user:***" : "none")));
        _dbgv($debug, "    Timeout:        $timeout sec");
        _dbgv($debug, "    Payload size:   " . length($payload) . " bytes");
        _dbgv($debug, "    max_tokens:     100");
        _dbgv($debug, "    temperature:    0");
    }

    # ── Execute curl via IPC::Open3 (taint-safe) ──────────────────────────────
    require IPC::Open3;
    require Symbol;

    my @cmd = (
        'curl', '-s', '-S',
        '--max-time', $timeout,
        '-X', 'POST',
        '-H', 'Content-Type: application/json',
        '-H', 'Accept: application/json',
    );

    if ($api_key) {
        push @cmd, '-H', "Authorization: Bearer $api_key";
    } elsif ($url_user && $url_pass) {
        push @cmd, '-u', "$url_user:$url_pass";
    }

    push @cmd, '--data-binary', '@-', $url;

    _dbgv($debug, "  [_call_ai] Executing curl...");

    my $response = '';
    eval {
        local $SIG{ALRM} = sub { die "timeout\n" };
        alarm($timeout + 2);

        my $err_fh = Symbol::gensym();
        my $pid    = IPC::Open3::open3(my $in_fh, my $out_fh, $err_fh, @cmd);

        print $in_fh $payload;
        close $in_fh;

        while (<$out_fh>) { $response .= $_ }
        close $out_fh;
        close $err_fh;

        waitpid($pid, 0);
        alarm(0);
    };

    if ($@ || !$response) {
        my $err = $@ // 'empty response';
        _dbgv($debug, "  [_call_ai] curl FAILED: $err");
        dbg("LLMAssassin: curl error or timeout: $err");
        return (undef, undef, undef);
    }

    _dbgv($debug, "  [_call_ai] curl succeeded. Response length: " . length($response) . " bytes");
    _dbgv($debug, "  [_call_ai] Raw response: $response");

    # ── Extract content field ─────────────────────────────────────────────────
    # The content field is a JSON-encoded string — it may contain escaped quotes
    # (\") and the field may be followed by other fields like "padding":"...".
    # We must match the full escaped string value, not stop at the first quote.
    _dbgv($debug, "  [_call_ai] Extracting 'content' field from response JSON...");
    my ($http_content) = $response =~ /"content"\s*:\s*"((?:[^"\\]|\\.)*)"/s;
    unless ($http_content) {
        _dbgv($debug, "  [_call_ai] ERROR: could not find 'content' field in response");
        dbg("LLMAssassin: could not extract content from response: $response");
        return (undef, undef, undef);
    }

    _dbgv($debug, "  [_call_ai] Raw content field: $http_content");

    # ── Unescape ──────────────────────────────────────────────────────────────
    _dbgv($debug, "  [_call_ai] Unescaping JSON string...");
    $http_content =~ s/\\n/\n/g;
    $http_content =~ s/\\"/"/g;
    $http_content =~ s/\\\\/\\/g;
    $http_content =~ s/^```(?:json)?\s*//i;
    $http_content =~ s/\s*```$//;
    $http_content = _trim($http_content);

    _dbgv($debug, "  [_call_ai] Unescaped content: $http_content");

    # ── Parse fields ──────────────────────────────────────────────────────────
    _dbgv($debug, "  [_call_ai] Parsing spam / confidence / reason fields...");

    my ($spam_val) = $http_content =~ /"spam"\s*:\s*(true|false)/i;
    my ($conf_val) = $http_content =~ /"confidence"\s*:\s*([\d.]+)/i;
    my ($reason)   = $http_content =~ /"reason"\s*:\s*"((?:[^"\\]|\\.)*)"/i;

    _dbgv($debug, "  [_call_ai] spam_val  = " . (defined $spam_val ? $spam_val : 'UNDEF — regex did not match'));
    _dbgv($debug, "  [_call_ai] conf_val  = " . (defined $conf_val ? $conf_val : 'UNDEF — using default'));
    _dbgv($debug, "  [_call_ai] reason    = " . (defined $reason   ? $reason   : 'UNDEF — regex did not match'));

    unless (defined $spam_val) {
        _dbgv($debug, "  [_call_ai] ERROR: could not parse spam field. Full content was: $http_content");
        dbg("LLMAssassin: could not parse response JSON: $http_content");
        return (undef, undef, undef);
    }

    my $is_spam    = (lc($spam_val) eq 'true') ? 1 : 0;
    my $confidence = defined $conf_val ? $conf_val + 0 : ($is_spam ? 1.0 : 0.0);
    $reason      //= 'No reason provided';

    _dbgv($debug, "  [_call_ai] Final parsed result: is_spam=$is_spam confidence=$confidence reason=$reason");

    return ($is_spam, $confidence, $reason);
}

# ── Minimal JSON encoder (no CPAN dependency) ─────────────────────────────────
sub _json_encode {
    my ($data) = @_;
    if (ref $data eq 'HASH') {
        my @pairs;
        for my $k (sort keys %$data) {
            push @pairs, _json_str($k) . ':' . _json_encode($data->{$k});
        }
        return '{' . join(',', @pairs) . '}';
    }
    if (ref $data eq 'ARRAY') {
        return '[' . join(',', map { _json_encode($_) } @$data) . ']';
    }
    if (!defined $data)                             { return 'null' }
    if ($data =~ /^-?\d+(\.\d+)?$/ && !ref $data) { return $data  }
    return _json_str($data);
}

sub _json_str {
    my ($s) = @_;
    $s =~ s/\\/\\\\/g;
    $s =~ s/"/\\"/g;
    $s =~ s/\n/\\n/g;
    $s =~ s/\r/\\r/g;
    $s =~ s/\t/\\t/g;
    return '"' . $s . '"';
}

sub _trim { my $s = shift; $s =~ s/^\s+|\s+$//g; $s }

1;

__END__

=head1 NAME

Mail::SpamAssassin::Plugin::LLMAssassin - AI-powered spam detection via OpenAI-compatible APIs

=head1 SYNOPSIS

In C</etc/spamassassin/llmassassin.pre>:

  loadplugin Mail::SpamAssassin::Plugin::LLMAssassin /etc/spamassassin/LLMAssassin.pm

In C</etc/spamassassin/llmassassin.cf>:

  llm_api_base              https://user:pass@your-server.example.com
  llm_model                 gpt-4.1
  llm_spam_score            6.0
  llm_fail_closed           0
  llm_dry_run               0
  llm_skip_authenticated    1
  llm_max_calls_per_minute  0
  llm_score_map             0.9-1.0=8.0,0.7-0.9=5.0,0.5-0.7=2.0
  llm_debug                 0

  header   LLM_SPAM_CHECK  eval:check_llm_spam()
  describe LLM_SPAM_CHECK  LLM classified this email as spam
  score    LLM_SPAM_CHECK  6.0

  # Optional: add AI verdict to mail headers
  add_header all LLM-Spam-Reason   _LLMSPAMREASON_
  add_header all LLM-Confidence    _LLMSPAMCONFIDENCE_

=head1 DESCRIPTION

LLMAssassin is a SpamAssassin plugin that classifies email using any
OpenAI-compatible LLM API. It passes the LLM a rich context including:

=over 4

=item * Email headers and full Received chain

=item * DKIM, SPF, DMARC and ARC authentication results

=item * SpamAssassin's own score, Bayes probability, and fired rules

=item * All URLs extracted from the body

=item * Attachment filenames and MIME types

=item * Plain text body (truncated to llm_max_body_chars)

=back

The AI returns a spam verdict, confidence score (0.0-1.0), and a short reason.
Confidence maps to SA scores via C<llm_score_map> for fine-grained control.

=head1 CONFIGURATION

=over 4

=item B<llm_api_base> (default: https://api.openai.com)

Base URL of the OpenAI-compatible API. Supports embedded credentials:
C<https://user:pass@your-server.example.com>

=item B<llm_api_key> (default: empty)

Bearer token. Sent as C<Authorization: Bearer <key>>.
Takes priority over credentials in llm_api_base if both are set.

=item B<llm_model> (default: gpt-4.1)

Model name passed to the API.

=item B<llm_timeout> (default: 15)

Seconds before the API call times out.

=item B<llm_spam_score> (default: 6.0)

Flat score added when AI says spam. Overridden by llm_score_map if set.

=item B<llm_score_map> (default: empty)

Map confidence ranges to SA scores. Format: C<low-high=score,...>
Example: C<0.9-1.0=8.0,0.7-0.9=5.0,0.5-0.7=2.0>

=item B<llm_fail_closed> (default: 0)

C<0> = fail open (score 0 on error). C<1> = fail closed (apply llm_fail_score).

=item B<llm_fail_score> (default: 0.0)

Score applied on failure when llm_fail_closed is 1.

=item B<llm_dry_run> (default: 0)

C<1> = call API and log but never affect SA score.

=item B<llm_skip_authenticated> (default: 0)

C<1> = skip AI check for SMTP-authenticated senders.

=item B<llm_max_calls_per_minute> (default: 0)

Rate limit on API calls per minute. C<0> = unlimited.

=item B<llm_max_body_chars> (default: 8000)

Max body characters sent to AI.

=item B<llm_system_prompt> (default: built-in)

Override the system prompt. Must instruct the model to return:
C<{"spam": true/false, "confidence": 0.0-1.0, "reason": "..."}>

=item B<llm_rate_file> (default: /tmp/llmassassin.rate)

Path to the rate limiter state file.

=item B<llm_rewrite_subject> (default: 1)

C<1> = prepend C<[LLMAssassin: reason]> to the Subject header when the AI
classifies the message as spam. Example:

  Subject: [LLMAssassin: Unsolicited marketing offer] Original subject here

C<0> = do not modify the Subject header.

=item B<llm_send_sa_signals> (default: 1)

C<1> = include SpamAssassin content signals (Bayes probability, content rules)
in the prompt. Authentication and reputation signals (DKIM, SPF, IP reputation,
whitelists) are intentionally excluded even when this is enabled — they are
already visible in the raw headers and would otherwise cause the LLM to
over-weight sender reputation and ignore content.
C<0> = omit all SA signals entirely.

=item B<llm_debug> (default: 0)

C<1> = verbose step-by-step debug logging via SA's dbg() system.
View with: C<tail -f /var/log/mail.log | grep LLMAssassin>

=back

=head1 SA TAGS

  _LLMSPAMREASON_      — Short reason from the AI
  _LLMSPAMCONFIDENCE_  — Confidence percentage (e.g. "94%")

=head1 AUTHOR

Albus / Patronum

=head1 LICENSE

Apache License 2.0

=cut